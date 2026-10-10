// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the brain wire protocol.
//!
//! **WHY this file and not the other 4100 lines of `domains/robot/behavior`.** These
//! functions parse bytes that arrive over TCP from the brain server, which is
//! a separate process on another machine — the same class as the DNS and NTP
//! parsers, and the same consequence: with `panic = "abort"` a reachable panic
//! here is a board reset an off-path attacker can trigger.
//!
//! And one of them decodes **actuator commands**. A wrong decode is not an
//! error the robot reports; it is a movement it performs.
//!
//! The module is pulled in with `#[path]`, so the code under test is the code
//! that ships.

// The driver class crates the compiled sources name, all served by the
// one host stand-in `beh_test_drivers`.
extern crate beh_test_drivers as azos_drv_actuator;
extern crate beh_test_drivers as azos_drv_gpio;
extern crate beh_test_drivers as azos_drv_irqchip;
extern crate beh_test_drivers as azos_drv_sys;

#[allow(dead_code)]
#[path = "../../../../domains/robot/behavior/src/brain_protocol.rs"]
// Named for the file it is, not shortened: `remote.rs` — pulled in below —
// refers to `crate::brain_protocol`, and a suite that renames a module makes
// the code under test stop resolving against itself.
mod brain_protocol;

#[cfg(test)]
mod framing {
    use super::brain_protocol::*;

    /// Build a well-formed packet: magic, type, little-endian length, payload,
    /// CRC-8 over header+payload.
    fn packet(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![MAGIC[0], MAGIC[1], kind,
                         (payload.len() & 0xFF) as u8,
                         (payload.len() >> 8) as u8];
        p.extend_from_slice(payload);
        let crc = crc8(&p[..5 + payload.len()]);
        p.push(crc);
        p
    }

    #[test]
    fn a_well_formed_packet_parses_to_its_payload_window() {
        let pkt = packet(PKT_ACTUATOR, &[1, 2, 3, 4]);
        let (kind, off, len, total) = parse_packet(&pkt).expect("valid packet");
        assert_eq!(kind, PKT_ACTUATOR);
        assert_eq!(&pkt[off..off + len], &[1, 2, 3, 4]);
        assert_eq!(total, pkt.len());
    }

    /// **The CRC is the only thing standing between a corrupted frame and the
    /// actuators.** Accepting a good packet proves nothing about validation —
    /// a parser that ignores the CRC accepts it too. Flipping one payload bit
    /// without recomputing must be refused, and so must a wrong CRC byte.
    #[test]
    fn a_corrupt_packet_is_refused() {
        let good = packet(PKT_ACTUATOR, &[1, 2, 3, 4]);
        let mut bit = good.clone();
        bit[6] ^= 0x01;                       // one payload bit
        assert!(parse_packet(&bit).is_none(), "payload bit flip must fail CRC");
        let mut crc = good.clone();
        let last = crc.len() - 1;
        crc[last] ^= 0xFF;                    // the CRC byte itself
        assert!(parse_packet(&crc).is_none(), "wrong CRC must be refused");
    }

    /// The magic gates the whole stream: without it any TCP peer that reaches
    /// the port is speaking the protocol.
    #[test]
    fn a_wrong_magic_is_refused() {
        let mut p = packet(PKT_ACTUATOR, &[1]);
        p[0] = b'X';
        assert!(parse_packet(&p).is_none());
        let mut p = packet(PKT_ACTUATOR, &[1]);
        p[1] = b'X';
        assert!(parse_packet(&p).is_none());
    }

    /// **A length field longer than the buffer must not read past it.** The
    /// length is two attacker-controlled bytes, so it can claim up to 65535
    /// while the buffer holds a handful — the exact shape of the `ip.rs`
    /// defect where a crafted `total_length` produced a reversed range.
    #[test]
    fn a_length_beyond_the_buffer_is_refused_not_read() {
        let mut p = packet(PKT_ACTUATOR, &[1, 2, 3, 4]);
        p[3] = 0xFF;
        p[4] = 0xFF;                          // claims 65535 bytes
        assert!(parse_packet(&p).is_none());
    }

    /// Truncation at every length must be refused and must not panic. A
    /// stream reassembler hands over whatever has arrived so far, so every
    /// prefix of a real packet reaches this function in normal operation.
    #[test]
    fn every_truncation_is_refused_without_panicking() {
        let full = packet(PKT_ACTUATOR, &[1, 2, 3, 4]);
        for n in 0..full.len() {
            assert!(parse_packet(&full[..n]).is_none(),
                    "a {n}-byte prefix must not parse");
        }
        assert!(parse_packet(&full).is_some(), "the whole packet still parses");
    }
}

#[cfg(test)]
mod actuator {
    use super::brain_protocol::*;

    /// Channels are little-endian i16, and the sign matters: a byte-order or
    /// sign mistake still produces a legal PWM value, so the motor turns the
    /// wrong way rather than the command being rejected.
    #[test]
    fn channels_are_signed_little_endian() {
        // type=0, n=2, flags=0, then -300 and +300 as LE i16.
        let mut p = vec![0u8, 2, 0];
        p.extend_from_slice(&(-300i16).to_le_bytes());
        p.extend_from_slice(&(300i16).to_le_bytes());
        let c = decode_actuator_cmd(&p).expect("well-formed command");
        assert_eq!(c.n_channels, 2);
        assert_eq!(c.channels[0], -300, "reverse must stay reverse");
        assert_eq!(c.channels[1], 300);
    }

    /// **A channel count larger than the array must not overflow it.** `n` is
    /// one attacker-controlled byte (up to 255) against `MAX_CHANNELS` (8).
    /// The payload must be long enough for the claim *and* only MAX_CHANNELS
    /// may be written — dropping either half is an out-of-bounds write of
    /// actuator values.
    #[test]
    fn an_oversized_channel_count_cannot_overflow_the_array() {
        // Claims 255 channels and actually supplies the bytes for them.
        let mut p = vec![0u8, 255, 0];
        for i in 0..255i16 { p.extend_from_slice(&i.to_le_bytes()); }
        let c = decode_actuator_cmd(&p).expect("long but well-formed");
        assert_eq!(c.n_channels as usize, MAX_CHANNELS,
                   "only MAX_CHANNELS may be accepted");
        // Claims 255 channels but supplies none: must be refused outright.
        assert!(decode_actuator_cmd(&[0, 255, 0]).is_none(),
                "a count the payload cannot back must be refused");
    }

    /// A payload shorter than the fixed header is refused rather than indexed.
    #[test]
    fn a_short_payload_is_refused() {
        for n in 0..3usize {
            assert!(decode_actuator_cmd(&vec![0u8; n]).is_none(),
                    "{n} bytes is shorter than the 3-byte header");
        }
        // Exactly the header with zero channels is legal.
        let c = decode_actuator_cmd(&[0, 0, 0]).expect("zero channels is legal");
        assert_eq!(c.n_channels, 0);
    }

    /// An empty predict payload must not slice `[len - 1]` on an empty slice —
    /// that is an underflow and a panic, i.e. a board reset from one byte
    /// short on the wire.
    #[test]
    fn an_empty_predict_payload_does_not_underflow() {
        assert!(decode_predict_cmd(&[]).is_none());
    }
}

#[allow(dead_code)]
#[path = "../../../../domains/robot/behavior/src/types.rs"]
mod types;

// `remote.rs` holds the bridge from a decoded `ActuatorCmd` to the behaviour
// action — see `remote_actuation_from`. Pulled here rather than left to the
// real crate for the same reason as `types` and `safety` above: the code under
// test is the code the kernel ships.
#[allow(dead_code)]
#[path = "../../../../domains/robot/behavior/src/remote.rs"]
mod remote;

#[allow(dead_code)]
#[path = "../../../../domains/robot/behavior/src/safety.rs"]
mod safety;

// The e-stop latch, its release authority and safe mode moved out of
// `safety.rs` into `crates/core/actuation/src/estop.rs` (wave 11, DOMAIN);
// `safety.rs` re-exports `crate::estop::*`, so the kernel and this crate both
// reach the latch through the same file. `hooks` is the table the latch
// runs the robot's on-latch work through.
#[allow(dead_code)]
#[path = "../../../../crates/core/actuation/src/estop.rs"]
mod estop;
#[allow(dead_code)]
#[path = "../../../../crates/core/actuation/src/hooks.rs"]
mod hooks;

// RED/GREEN tests for the 2026-09-25 owner decision (the brain may REQUEST an
// e-stop release, it may never CLEAR the latch). A NEW file, not folded into
// the `mode_reset` module below, per the wave's file-split: another agent
// owns actuation-record tests in this same crate. See its module doc for the
// full RED-to-GREEN account. `cfg(test)`, matching `envelope`/`mode_reset`
// below: it uses `ReleaseAuthority::for_test`/`test_reset_operator_authority`,
// both themselves `cfg(test)`-only in `safety.rs`.
#[cfg(test)]
mod estop_release_authority;

// ---------------------------------------------------------------------------
// Subsumption arbiter (`domains/robot/behavior/src/arbiter.rs`) and the layers +
// offline patrol it depends on (`layers.rs`, `offline.rs`) — pulled in by
// `#[path]` for the same reason as `types`/`safety` above: the code under
// test must be the code that ships, and the crate is `#![no_std]` so it
// cannot be a normal host dependency of this crate.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[path = "../../../../domains/robot/behavior/src/layers.rs"]
mod layers;

// Pulled in 2026-09-11, when `payload_cam_trigger`'s 50 ms busy-wait turned
// out to be reachable per-frame from a remote peer. It needs the shim's GPIO.
#[allow(dead_code)]
#[path = "../../../../domains/robot/behavior/src/payload.rs"]
mod payload;

#[allow(dead_code)]
#[path = "../../../../domains/robot/behavior/src/offline.rs"]
mod offline;

#[allow(dead_code)]
#[path = "../../../../domains/robot/behavior/src/arbiter.rs"]
mod arbiter;

// The producer side of the geofence: `update_gps`, the unit conversion and the
// staleness rule `snapshot` applies before `safety.rs` ever sees a fix.
#[allow(dead_code)]
#[path = "../../../../domains/robot/behavior/src/sensor_bus.rs"]
mod sensor_bus;

// The ring-3 ML verdict policy (what L1 gets when the ML service answers,
// is late, is gone, or was never started).
#[allow(dead_code)]
#[path = "../../../../domains/robot/behavior/src/ml_link.rs"]
mod ml_link;

#[cfg(test)]
mod envelope {
    use super::safety::*;

    /// The envelope reads process-wide state (e-stop, robot type, confidence,
    /// degrade level), so these must not interleave. `pub(super)` because the
    /// `geofence` module below reads the same ESTOP/robot-type statics
    /// (through `safety_check`) and must serialize against this one too, not
    /// just against its own tests.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    pub(super) fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Put every input back to its permissive default, so each test states its
    /// own preconditions instead of inheriting the previous one's.
    fn reset() {
        estop_release(ReleaseAuthority::for_test());
        safety_set_robot_type(ROBOT_TYPE_WHEELED);
        cmd_set_low_confidence(false);
        azos_ipc::shim_set_level(0);
    }

    /// **E-stop overrides everything, unconditionally.** Not "caps to a low
    /// speed" — zero. This is the one property that must hold whatever else is
    /// set, so it is checked against a command that would otherwise be legal.
    #[test]
    fn estop_forces_zero_whatever_else_is_set() {
        let _g = serial();
        reset();
        assert_eq!(motor_envelope(10, -10), (10, -10), "baseline: a small command passes");
        estop_activate();
        assert_eq!(motor_envelope(10, -10), (0, 0), "e-stop must zero a legal command");
        assert_eq!(motor_envelope(100, 100), (0, 0));
        assert_eq!(motor_envelope(i32::MAX, i32::MIN), (0, 0), "including extremes");
        estop_release(ReleaseAuthority::for_test());
        assert_eq!(motor_envelope(10, -10), (10, -10), "and it must be releasable");
    }

    /// **Reverse must be capped exactly like forward.** A clamp that bounds
    /// only the positive side is the classic asymmetry bug: it passes every
    /// forward test and lets full-speed reverse through.
    #[test]
    fn the_cap_is_symmetric() {
        let _g = serial();
        reset();
        let cap = SAFETY_WHEELED_MAX_SPEED_PCT as i32;
        assert_eq!(motor_envelope(100, 100), (cap, cap));
        assert_eq!(motor_envelope(-100, -100), (-cap, -cap), "reverse must be capped");
        assert_eq!(motor_envelope(i32::MIN, i32::MAX), (-cap, cap),
                   "extremes must saturate, not wrap");
    }

    /// **Constraints compose, and the tighter one wins.** Low confidence caps
    /// at 40 and the wheeled type at 80; applying them with `max`, or in the
    /// wrong order, lets the looser one through — which is a robot moving at
    /// twice the speed its own uncertainty allows.
    #[test]
    fn the_tighter_of_two_caps_wins() {
        let _g = serial();
        reset();
        let low = SAFETY_LOW_CONFIDENCE_CAP_PCT as i32;
        cmd_set_low_confidence(true);
        assert_eq!(motor_envelope(100, -100), (low, -low),
                   "low confidence must beat the wheeled cap");
        cmd_set_low_confidence(false);
        assert_eq!(motor_envelope(100, -100),
                   (SAFETY_WHEELED_MAX_SPEED_PCT as i32,
                    -(SAFETY_WHEELED_MAX_SPEED_PCT as i32)),
                   "and clearing it must restore the wider cap");
    }

    /// The graded degrade ceiling composes with the rest, and must be
    /// monotonic: a worse level can never permit MORE speed than a better one.
    /// That is the property a table of per-level constants is easy to break.
    #[test]
    fn a_worse_degrade_level_never_permits_more_speed() {
        let _g = serial();
        reset();
        let mut prev = i32::MAX;
        for level in 0..=4u8 {
            azos_ipc::shim_set_level(level);
            let (l, _) = motor_envelope(100, 100);
            assert!(l <= prev, "level {level} permits {l} after {prev}");
            assert!(l >= 0, "a cap must never be negative");
            prev = l;
        }
    }

    /// **Unknown degrade levels must fail closed**, i.e. to zero, not to the
    /// permissive default. A level the runtime does not yet produce is exactly
    /// what a future change introduces.
    #[test]
    fn an_unknown_degrade_level_fails_closed() {
        let _g = serial();
        reset();
        for level in [200u8, 255] {
            azos_ipc::shim_set_level(level);
            assert_eq!(motor_envelope(100, 100), (0, 0),
                       "unknown level {level} must not permit motion");
        }
    }

    /// The envelope must never amplify: the output magnitude cannot exceed the
    /// input's. A cap that replaces rather than bounds would turn a gentle
    /// command into a full-speed one.
    #[test]
    fn the_envelope_never_amplifies() {
        let _g = serial();
        reset();
        for v in [0i32, 1, 5, 37, 79, 80, 81, 100] {
            let (l, r) = motor_envelope(v, -v);
            assert!(l <= v && -r <= v, "input {v} produced ({l}, {r})");
        }
    }
}

// ---------------------------------------------------------------------------
// PKT_MODE e-stop reset gate (`domains/robot/behavior/src/brain_protocol.rs`,
// `MODE_ID_ESTOP_RESET` / `mode_estop_record` / `mode_degrade_record`).
//
// Owner decision, 2026-09-06: `PKT_ESTOP` only ever ARMS (grep it), so
// `PKT_MODE` is the only rearm path in the tree, and until this gate existed
// `decode_mode_cmd` handed back a byte NOTHING validated — any `mode_id`
// cleared an armed e-stop. `kernel/src/tasks/behavior.rs` has two dispatch sites (the
// TCP brain link and the `feature = "vf2"` UART bridge, compiled out of every
// QEMU build) that both now call `mode_estop_record`/`mode_degrade_record`
// and act on exactly what they return — no `if mode_id == ...` left inline at
// either call site.
//
// That is deliberate, and it is what these tests exercise: calling the SAME
// functions the dispatch sites call, not re-deriving the same `if` locally.
// A test built the second way (decode a mode, then write its own
// `if mode_clears_containment(...) { estop_release(proof) }`) would keep
// passing even if a future edit deleted the gate from `kernel/src/tasks/behavior.rs` entirely —
// it would only be pinning the predicate, not the wiring. These call
// `mode_estop_record` and act on its `(should_clear, action_code)`, against
// the REAL `safety.rs` e-stop state, so a regression at either call site —
// the gate deleted, or swapped for `mode_clears_containment(mode_id) || true`
// — fails here without needing QEMU or the vf2-only UART build.
//
// **`should_clear` alone is no longer the whole story.** Owner decision,
// 2026-09-25: `kernel/src/tasks/behavior.rs` now treats `should_clear == true` as "this MAY be an
// authorised release", not "clear it" — it additionally requires a verified
// `safety::ReleaseAuthority` (an operator-signed proof today; see
// `safety::verify_operator_release`'s module note) before it will actually
// call `estop_release`. The tests below still pin `mode_estop_record`'s pure
// predicate correctly (that part of the gate is unchanged), and use
// `ReleaseAuthority::for_test()` — a proof constructor that exists only under
// `cfg(test)`, never in a kernel binary — to drive `safety.rs` the rest of
// the way, standing in for the authority check `kernel/src/tasks/behavior.rs` performs for real.
// The authority check itself (request-does-not-clear, valid-signature-does,
// forged/absent-signature-refused, replay-refused) is pinned in
// `estop_release_authority.rs`, a NEW file rather than a rewrite of this one.
//
// Degraded-mode clearing (RFC-0036) goes through `mode_degrade_record`, the
// sibling function gated on the exact same reserved id — see the gate's doc
// comment in `kernel/src/tasks/behavior.rs` for why. The real `degraded_set`/`degraded_active`
// (`crates/core/ipc::cap`) are not reachable from this host-test crate, which only
// links the level shim in `shims/ipc` (see
// `envelope::a_worse_degrade_level_never_permits_more_speed` above), so its
// tests check the returned tuple directly rather than driving a real
// degraded-mode flag.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod mode_reset {
    use super::brain_protocol::*;
    use super::safety::*;

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        super::envelope::serial()
    }

    /// `0xFF`, not `0`, and not a small value either — see the constant's own
    /// doc comment in `brain_protocol.rs` for the full reasoning. A zeroed or
    /// truncated payload reads as `mode_id == 0` by default, so `0` would let
    /// the single most common malformed-frame case rearm the robot.
    #[test]
    fn the_reserved_id_is_not_zero_or_a_small_value() {
        assert_ne!(MODE_ID_ESTOP_RESET, 0);
        assert!(MODE_ID_ESTOP_RESET > 2,
                "small ids are the likeliest candidates for real operating modes");
    }

    /// An e-stop that is not armed has nothing to clear and nothing to
    /// refuse — `mode_estop_record` must say so explicitly (`None`), not
    /// silently agree with whatever the caller assumes.
    #[test]
    fn an_unarmed_estop_records_nothing() {
        assert_eq!(mode_estop_record(MODE_ID_ESTOP_RESET, false), None);
        assert_eq!(mode_estop_record(0, false), None);
    }

    /// **The positive half, against the real e-stop state.** `mode_estop_record`
    /// — the exact function both `kernel/src/tasks/behavior.rs` dispatch sites call — must say
    /// "clear" for the reserved id, and driving `safety.rs` off that answer
    /// (the same way `kernel/src/tasks/behavior.rs` is written to) must actually clear it.
    #[test]
    fn the_reserved_id_clears_an_armed_estop() {
        let _g = serial();
        estop_release(ReleaseAuthority::for_test());
        estop_activate();
        assert!(estop_is_active(), "precondition: armed");

        let mode = decode_mode_cmd(&[MODE_ID_ESTOP_RESET]).expect("1-byte payload");
        let (should_clear, action_code) = mode_estop_record(mode.mode_id, estop_is_active())
            .expect("estop is armed, so this must record something");
        assert!(should_clear, "the reserved id must say 'clear'");
        assert_eq!(action_code, 3, "a real clear must not be confused with a refusal");
        if should_clear {
            estop_release(ReleaseAuthority::for_test());
        }
        assert!(!estop_is_active(), "reserved id must clear the e-stop");
    }

    /// **The negative half that matters most.** Every OTHER mode id —
    /// including 0, the byte a zeroed or truncated payload reads as — must
    /// make `mode_estop_record` say "do not clear", and driving `safety.rs`
    /// off that answer must leave an armed e-stop exactly as armed as it
    /// found it. A test that only checks the reserved id passes against code
    /// that clears on everything, which is the bug this whole gate exists to
    /// close.
    #[test]
    fn any_other_mode_id_leaves_an_armed_estop_armed() {
        let _g = serial();
        for id in [0u8, 1, 2, 0x7F, 0x80, 0xFE] {
            estop_release(ReleaseAuthority::for_test());
            estop_activate();
            assert!(estop_is_active(), "precondition: armed");

            let mode = decode_mode_cmd(&[id]).expect("1-byte payload");
            let (should_clear, action_code) = mode_estop_record(mode.mode_id, estop_is_active())
                .expect("estop is armed, so this must record something");
            assert!(!should_clear, "mode_id={id} must say 'do not clear'");
            assert_eq!(action_code, 4, "a refusal must not be confused with a real clear");
            if should_clear {
                estop_release(ReleaseAuthority::for_test());
            }
            assert!(estop_is_active(), "mode_id={id} must NOT clear the e-stop");
        }
        estop_release(ReleaseAuthority::for_test()); // leave global state clean for tests that follow
    }

    /// `decode_mode_cmd` on an empty payload must refuse rather than index —
    /// a truncated `PKT_MODE` frame must not panic, and must not be silently
    /// treated as carrying `mode_id == 0` either (it carries no mode id).
    #[test]
    fn an_empty_mode_payload_is_refused_not_defaulted() {
        assert!(decode_mode_cmd(&[]).is_none());
    }

    /// The degraded-mode sibling of the two tests above: same reserved id,
    /// same shape, distinct (and non-colliding) `action_code`s from the
    /// `SAFETY_DEGRADE` codes `PKT_DEGRADE` itself already uses (0 = full
    /// authority restored, 1 = armed with a reason). `detail` on a refusal
    /// carries the rejected `mode_id`, mirroring the e-stop refusal.
    #[test]
    fn degraded_mode_is_gated_on_the_same_reserved_id() {
        assert_eq!(mode_degrade_record(MODE_ID_ESTOP_RESET, false), None,
                   "not active: nothing to clear or refuse");

        let (clear, action, detail) = mode_degrade_record(MODE_ID_ESTOP_RESET, true)
            .expect("active, so this must record something");
        assert!(clear, "the reserved id must clear degraded mode too");
        assert_eq!((action, detail), (0, 1));

        for id in [0u8, 1, 2, 0x7F, 0x80, 0xFE] {
            let (clear, action, detail) = mode_degrade_record(id, true)
                .expect("active, so this must record something");
            assert!(!clear, "mode_id={id} must NOT clear degraded mode");
            assert_eq!(action, 2, "a refusal must not collide with 0 (cleared) or 1 (armed)");
            assert_eq!(detail, id as u32, "detail must carry the rejected mode_id");
        }
    }
}

// ---------------------------------------------------------------------------
// E03 geofence (`domains/robot/behavior/src/safety.rs`, `check_geofence_from_gps`
// down to `GeofenceStatus`).
//
// The first tests inject a fix directly into `SensorState` and pin the math
// and the dispatch. The later ones start one step earlier, at
// `SensorBus::update_gps` in the driver's units, so the conversion to
// micro-degrees, the snapshot and the staleness rule are the code under test
// too. What stays out of reach here: the kernel's `update_gps` call on the
// `CH_GPS` publish, which the `geofence-smoke` QEMU probe covers. The boot's
// own arm (`geofence_arm_home`, wave 15) is `geofence_home_arm` below; the
// `fence-refuse-smoke` QEMU rows cover it end to end.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod geofence {
    use super::safety::*;
    use super::types::*;

    /// `safety_check` reads the same ESTOP/robot-type statics `motor_envelope`
    /// does (`envelope` module above), plus the geofence's own `GEOFENCE`
    /// lock — sharing one mutex keeps every test in the file that touches
    /// this process-wide state from interleaving with any other.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        super::envelope::serial()
    }

    /// Put every input back to a known, permissive baseline.
    fn reset() {
        estop_release(ReleaseAuthority::for_test());
        safety_set_robot_type(ROBOT_TYPE_WHEELED);
        geofence_disable();
        // `check_common`'s IMU-staleness tracker (`IMU_INVALID_SINCE`) is a
        // process-wide static keyed off the REAL clock (this module never
        // pins it) — an earlier test elsewhere in the suite that DOES pin
        // the clock to a large fixed value (`flight_recorder::begin`,
        // `envelope`'s wire tests) can leave `since` set from a totally
        // different clock regime, making the very next call here see a
        // huge bogus `elapsed`. Reset before every test, same reason
        // `estop_release`/`geofence_disable` are here.
        test_reset_imu_incoherence();
    }

    /// A default snapshot has `gps_fix = 0`, so a position built from it is
    /// never mistaken for a trusted fix by accident — each test opts in to a
    /// fix explicitly.
    fn far_outside_fix() -> SensorState {
        let mut s = SensorState::new();
        s.gps_fix = 3;
        s.gps_satellites = 8;
        s.gps_lat_udeg = 0;
        s.gps_lon_udeg = 10_000_000; // 10 deg east of centre ~= 1110 km
        s
    }

    /// **The test that fails if the math or the wiring is broken.** A
    /// position ~1110 km from a 10 m fence is unambiguously outside; if this
    /// does not fire, nothing below is worth trusting.
    #[test]
    fn a_configured_fence_catches_a_position_far_outside_it() {
        let _g = serial();
        reset();
        geofence_set(0, 0, 10);
        let r = safety_check(&far_outside_fix());
        assert_eq!(r.violation, SafetyViolation::GeofenceViolation,
            "~1110 km outside a 10 m fence must be flagged");
        assert_eq!(r.action, SafetyAction::EmergencyStop,
            "wheeled cannot RTL, so a breach must e-stop");
    }

    /// The centre of the same fence must read as compliant — otherwise the
    /// test above could pass against code that reports a violation no
    /// matter what position is given.
    #[test]
    fn a_configured_fence_passes_a_position_at_its_centre() {
        let _g = serial();
        reset();
        geofence_set(0, 0, 10);
        let mut s = SensorState::new();
        s.gps_fix = 3;
        s.gps_satellites = 8;
        s.gps_lat_udeg = 0;
        s.gps_lon_udeg = 0;
        let r = safety_check(&s);
        assert_eq!(r.violation, SafetyViolation::None,
            "the fence centre itself must read as inside");
        assert_eq!(r.action, SafetyAction::None);
    }

    /// **A breach latches the stop and says how far out it was** (owner
    /// decision 2026-09-16). Before it, L0 commanded (0, 0) only while the
    /// reading said `Outside`.
    #[test]
    fn a_breach_latches_the_estop_and_reports_the_overshoot() {
        let _g = serial();
        reset();
        geofence_set(0, 0, 10);
        let s = far_outside_fix();
        let overshoot = geofence_breach_latch(&s)
            .expect("a position outside the fence must latch the stop");
        assert!(estop_is_active(), "the breach must hold the machine");
        assert!(overshoot > 1_000_000,
                "~1110 km beyond a 10 m fence, got {overshoot} m");
        reset();
    }

    /// One record per breach, not one per tick: the latch is the guard. A
    /// behaviour loop at 10 Hz would otherwise fill the recorder with the
    /// same breach and evict everything else in it.
    #[test]
    fn a_held_latch_does_not_report_the_same_breach_again() {
        let _g = serial();
        reset();
        geofence_set(0, 0, 10);
        let s = far_outside_fix();
        assert!(geofence_breach_latch(&s).is_some(), "first breach latches");
        assert!(geofence_breach_latch(&s).is_none(),
                "a held latch must not be recorded a second time");
        reset();
    }

    /// **The point of the decision.** Once latched, the machine stays stopped
    /// when the reading stops saying `Outside` — including the case that made
    /// this reachable in practice, a fix going stale and reading `Unknown`.
    /// Only an operator clear releases it.
    #[test]
    fn the_latch_holds_after_the_reading_stops_saying_outside() {
        let _g = serial();
        reset();
        geofence_set(0, 0, 10);
        assert!(geofence_breach_latch(&far_outside_fix()).is_some());

        let mut stale = far_outside_fix();
        stale.gps_fix = 0; // what `SensorBus::snapshot` leaves on a stale fix
        stale.gps_satellites = 0;
        assert_eq!(geofence_status(&stale), GeofenceStatus::Unknown,
                   "a stale fix is not a position");
        assert!(geofence_breach_latch(&stale).is_none(),
                "no second breach to report");
        assert!(estop_is_active(),
                "the latch must survive the reading going Unknown");

        let mut inside = far_outside_fix();
        inside.gps_lon_udeg = 0;
        assert_eq!(geofence_status(&inside), GeofenceStatus::Inside);
        assert!(estop_is_active(),
                "coming back inside must not release an operator-cleared latch");
        reset();
        assert!(!estop_is_active(), "an operator clear releases it");
    }

    /// A fence acts on a MEASURED position. 6 (dead reckoning), 7 (manual
    /// entry) and 8 (simulator) carry a position the receiver did not
    /// measure, and a fence acting on one stops the machine on a number
    /// somebody typed — or, worse, reads a drifting dead-reckoned position as
    /// inside. Owner decision 2026-09-16; 3 (PPS) is a real fix and stays in.
    #[test]
    fn only_measured_fix_qualities_move_the_fence() {
        let _g = serial();
        reset();
        geofence_set(0, 0, 10);
        for q in [1u8, 2, 3, 4, 5] {
            let mut s = far_outside_fix();
            s.gps_fix = q;
            assert_eq!(geofence_status(&s), GeofenceStatus::Outside,
                       "quality {q} is a measured fix and must be acted on");
        }
        for q in [0u8, 6, 7, 8] {
            let mut s = far_outside_fix();
            s.gps_fix = q;
            assert_eq!(geofence_status(&s), GeofenceStatus::Unknown,
                       "quality {q} is not a measured position");
            assert!(geofence_breach_latch(&s).is_none(),
                    "quality {q} must not stop the machine");
        }
        assert!(!estop_is_active());
        reset();
    }

    /// **The negative half that matters.** Same far-outside position as the
    /// first test, same configured fence — but `gps_fix = 0`, i.e. no
    /// trustworthy fix, which is the ONLY state this actually occurs in
    /// today (see the module comment). This must fall through exactly like
    /// "inside", not act as though the robot were confirmed safe, and above
    /// all not act as though it were confirmed OUTSIDE either — an untrusted
    /// reading must produce no geofence action at all.
    #[test]
    fn a_configured_fence_with_no_gps_fix_does_not_act() {
        let _g = serial();
        reset();
        geofence_set(0, 0, 10);
        let mut s = far_outside_fix();
        s.gps_fix = 0;
        s.gps_satellites = 0;
        let r = safety_check(&s);
        assert_eq!(r.violation, SafetyViolation::None,
            "an untrustworthy fix must not trigger the fence");
        assert_eq!(r.action, SafetyAction::None);
    }

    /// A disabled fence (`radius_m == 0`) must never trigger even given a
    /// real fix and an extreme position — distinguishes "off" from
    /// "evaluated and compliant", which a plain bool return conflates.
    #[test]
    fn a_disabled_fence_never_triggers_even_with_a_real_fix() {
        let _g = serial();
        reset(); // reset() itself calls geofence_disable()
        let mut s = SensorState::new();
        s.gps_fix = 3;
        s.gps_satellites = 8;
        s.gps_lat_udeg = 89_000_000;
        s.gps_lon_udeg = 179_000_000;
        let r = safety_check(&s);
        assert_eq!(r.violation, SafetyViolation::None,
            "a disabled fence must not evaluate distance at all");
    }

    /// A drone breach must RTL, not e-stop: the two robot types diverge on
    /// `SafetyAction` even though both raise `GeofenceViolation`.
    #[test]
    fn a_drone_outside_its_fence_returns_to_launch_not_estop() {
        let _g = serial();
        reset();
        safety_set_robot_type(ROBOT_TYPE_DRONE);
        geofence_set(0, 0, 10);
        let r = safety_check(&far_outside_fix());
        assert_eq!(r.violation, SafetyViolation::GeofenceViolation);
        assert_eq!(r.action, SafetyAction::ReturnToLaunch,
            "a drone can fly back; it must RTL, not e-stop");
    }

    /// **The trust rule, at both of its edges.** Quality 1 with 4 satellites is
    /// the weakest fix the fence acts on; one less of either is `Unknown`, and
    /// an untrusted reading must produce no action. Literal numbers, not the
    /// constants, so moving a threshold is a failure here rather than a
    /// silent change of what the fence trusts.
    #[test]
    fn the_fence_acts_on_quality_one_with_four_satellites_and_nothing_less() {
        let _g = serial();
        reset();
        geofence_set(0, 0, 10);
        for (fix, sats, acts) in [(1u8, 4u8, true), (0, 9, false), (1, 3, false), (2, 12, true)] {
            let mut s = far_outside_fix();
            s.gps_fix = fix;
            s.gps_satellites = sats;
            let r = safety_check(&s);
            if acts {
                assert_eq!(r.violation, SafetyViolation::GeofenceViolation,
                    "quality {fix} with {sats} satellites must be trusted");
                assert_eq!(geofence_status(&s), GeofenceStatus::Outside);
            } else {
                assert_eq!(r.violation, SafetyViolation::None,
                    "quality {fix} with {sats} satellites must not be trusted");
                assert_eq!(geofence_status(&s), GeofenceStatus::Unknown);
            }
        }
    }

    use super::sensor_bus::{deg7_to_udeg, sample_is_fresh, SensorBus};

    /// The kernel's simulated fix (`crates/drivers/gps`, `gps_init`), in the driver's
    /// units: 48.1351000° N, 11.5820000° E, quality 1, 9 satellites.
    const SIM_LAT_DEG7: i32 = 481_351_000;
    const SIM_LON_DEG7: i32 = 115_820_000;
    /// The same point in micro-degrees, written out rather than computed with
    /// `deg7_to_udeg`: a conversion checked against itself cannot fail.
    const SIM_LAT_UDEG: i32 = 48_135_100;
    const SIM_LON_UDEG: i32 = 11_582_000;
    /// 0.009° north of it, ~1 km, in the driver's units.
    const NORTH_1KM_LAT_DEG7: i32 = 481_441_000;

    /// A fix published on the bus reaches the snapshot whole, in micro-degrees.
    #[test]
    fn a_published_fix_reaches_the_snapshot_in_micro_degrees() {
        let bus = SensorBus::new();
        bus.update_gps(SIM_LAT_DEG7, SIM_LON_DEG7, 1, 9);
        let t = bus.gps_updated_at.load(std::sync::atomic::Ordering::Relaxed);
        assert_ne!(t, 0, "an update must stamp the fix");
        let mut s = SensorState::new();
        bus.snapshot_at(&mut s, t);
        assert_eq!((s.gps_lat_udeg, s.gps_lon_udeg), (SIM_LAT_UDEG, SIM_LON_UDEG),
            "the snapshot must carry the position in micro-degrees");
        assert_eq!((s.gps_fix, s.gps_satellites), (1, 9),
            "the snapshot must carry the fix quality and satellites");
        assert_eq!(deg7_to_udeg(-1_234_567_890), -123_456_789, "south and west too");
    }

    /// **A stale fix is no fix.** Fresh one tick before the age limit, gone at
    /// it: quality and satellites both zero, the fence `Unknown`.
    #[test]
    fn a_fix_expires_exactly_at_its_age_limit() {
        let bus = SensorBus::new();
        bus.update_gps(SIM_LAT_DEG7, SIM_LON_DEG7, 1, 9);
        let t = bus.gps_updated_at.load(std::sync::atomic::Ordering::Relaxed);
        let max = SensorBus::GPS_MAX_AGE_TICKS;
        assert_eq!(max, 20_000_000, "2 s at the suite's 10 MHz timebase");

        let mut s = SensorState::new();
        bus.snapshot_at(&mut s, t + max - 1);
        assert_eq!((s.gps_fix, s.gps_satellites), (1, 9), "one tick short of the limit is fresh");

        let mut s = SensorState::new();
        bus.snapshot_at(&mut s, t + max);
        assert_eq!((s.gps_fix, s.gps_satellites), (0, 0), "at the limit the fix has expired");
        assert_eq!(geofence_status(&s), GeofenceStatus::Unknown);
    }

    /// The IMU's rule, which `snapshot_at` now judges at the `now` it is given:
    /// valid one tick before 200 ms, invalid at it. The GPS age limit must not
    /// have been bought by loosening the IMU's.
    #[test]
    fn an_imu_sample_expires_at_200_ms() {
        let bus = SensorBus::new();
        bus.update_imu([0, 0, 1000], [0, 0, 0]);
        let t = bus.imu_updated_at.load(std::sync::atomic::Ordering::Relaxed);
        let mut s = SensorState::new();
        bus.snapshot_at(&mut s, t + 2_000_000 - 1);
        assert!(s.imu_valid, "one tick short of 200 ms is fresh");
        let mut s = SensorState::new();
        bus.snapshot_at(&mut s, t + 2_000_000);
        assert!(!s.imu_valid, "at 200 ms the sample has expired");
    }

    /// **Wave 11: the IMU ages from ACQUISITION, not delivery.** A sample the
    /// driver read 200 ms ago and hands over now is already stale, however
    /// recently it reached the bus: the stale-sample canary's property, on
    /// the host. With `update_imu` (delivery time) the same sample reads
    /// fresh, which is what the kernel's IMU task did before.
    ///
    /// **Canary.** Make `update_imu_at` store `timebase::now()` instead of
    /// `acq`: the frozen sample reads valid.
    #[test]
    fn an_imu_sample_ages_from_its_acquisition_stamp() {
        let bus = SensorBus::new();
        let acq = 50_000_000u64;
        bus.update_imu_at([0, 0, 1000], [0, 0, 0], acq);
        assert_eq!(bus.imu_updated_at.load(std::sync::atomic::Ordering::Relaxed), acq);
        let mut s = SensorState::new();
        bus.snapshot_at(&mut s, acq + SensorBus::IMU_MAX_AGE_TICKS - 1);
        assert!(s.imu_valid, "one tick short of the bound, by acquisition");
        // Re-delivered with the same (frozen) stamp: still the old sample.
        bus.update_imu_at([0, 0, 1000], [0, 0, 0], acq);
        let mut s = SensorState::new();
        bus.snapshot_at(&mut s, acq + SensorBus::IMU_MAX_AGE_TICKS);
        assert!(!s.imu_valid, "a re-delivered old sample is stale");
    }

    /// **Wave 11: a silent receiver's last fix goes stale.** The driver keeps
    /// answering with the fix of its last sentence; published with that
    /// sentence's stamp, it expires two seconds after the receiver went
    /// quiet, however often it is re-published, and the fence reads
    /// `Unknown`. A fix with no acquisition time (`acq == 0`, no sentence
    /// ever parsed) is never fresh.
    ///
    /// **Canary.** Make `update_gps_at` stamp `timebase::now()`: the
    /// re-published fix stays fresh and the fence keeps reading `Inside`.
    #[test]
    fn a_republished_fix_ages_from_its_sentence() {
        let _g = serial();
        reset();
        geofence_set(SIM_LAT_UDEG, SIM_LON_UDEG, 100);
        let bus = SensorBus::new();
        let sentence = 30_000_000u64;
        bus.update_gps_at(SIM_LAT_DEG7, SIM_LON_DEG7, 1, 9, sentence);
        let mut s = SensorState::new();
        bus.snapshot_at(&mut s, sentence + 1);
        assert_eq!(geofence_status(&s), GeofenceStatus::Inside);
        // The AHRS task re-publishes the same driver fix 3 s later.
        let later = sentence + SensorBus::GPS_MAX_AGE_TICKS + 10_000_000;
        bus.update_gps_at(SIM_LAT_DEG7, SIM_LON_DEG7, 1, 9, sentence);
        let mut s = SensorState::new();
        bus.snapshot_at(&mut s, later);
        assert_eq!((s.gps_fix, s.gps_satellites), (0, 0), "the silent receiver's fix expired");
        assert_eq!(geofence_status(&s), GeofenceStatus::Unknown);

        bus.update_gps_at(SIM_LAT_DEG7, SIM_LON_DEG7, 1, 9, 0);
        let mut s = SensorState::new();
        bus.snapshot_at(&mut s, 1);
        assert_eq!(s.gps_fix, 0, "a fix never acquired is never fresh");
        reset();
    }

    /// The freshness predicate on its own: never-updated is never fresh, and
    /// the bound is exclusive.
    #[test]
    fn freshness_is_exclusive_and_zero_is_never() {
        assert!(!sample_is_fresh(0, 0, 10), "zero is the never-updated sentinel");
        assert!(!sample_is_fresh(0, 5, 10));
        assert!(sample_is_fresh(100, 100, 10));
        assert!(sample_is_fresh(100, 109, 10));
        assert!(!sample_is_fresh(100, 110, 10));
    }

    /// **End to end from the bus: inside, then outside, then stale.** A fence
    /// of 100 m around the simulated fix, given in micro-degrees; the bus fed
    /// in the driver's units. Inside must be clean, 1 km north must be a
    /// violation, and the same far fix aged past the limit must stop acting.
    #[test]
    fn a_bus_fix_drives_the_fence_inside_outside_and_stale() {
        let _g = serial();
        reset();
        geofence_set(SIM_LAT_UDEG, SIM_LON_UDEG, 100);
        let bus = SensorBus::new();

        bus.update_gps(SIM_LAT_DEG7, SIM_LON_DEG7, 1, 9);
        let t = bus.gps_updated_at.load(std::sync::atomic::Ordering::Relaxed);
        let mut s = SensorState::new();
        bus.snapshot_at(&mut s, t);
        assert_eq!(geofence_status(&s), GeofenceStatus::Inside,
            "the fence centre, published through the bus, must read inside");
        assert_eq!(safety_check(&s).violation, SafetyViolation::None);

        bus.update_gps(NORTH_1KM_LAT_DEG7, SIM_LON_DEG7, 1, 4);
        let t = bus.gps_updated_at.load(std::sync::atomic::Ordering::Relaxed);
        let mut s = SensorState::new();
        bus.snapshot_at(&mut s, t);
        let r = safety_check(&s);
        assert_eq!(r.violation, SafetyViolation::GeofenceViolation,
            "1 km outside a 100 m fence must be flagged");
        assert_eq!(r.action, SafetyAction::EmergencyStop);

        let mut s = SensorState::new();
        bus.snapshot_at(&mut s, t + SensorBus::GPS_MAX_AGE_TICKS);
        assert_eq!(geofence_status(&s), GeofenceStatus::Unknown,
            "a stale fix must not keep reporting a position");
        assert_eq!(safety_check(&s).violation, SafetyViolation::None);
        reset();
    }
}

#[cfg(test)]
mod imu_incoherence {
    //! Owner decision, 2026-09-26 (V1.6): a dead IMU must stop the robot
    //! after a bounded grace period, not read as "nothing to check" forever
    //! (the pre-decision behaviour every OTHER `geofence`/`arbitration`
    //! fixture relies on for the FIRST ~200 ms-to-1 s of a boot, before the
    //! first real sample arrives — those fixtures still pass unmodified;
    //! only a stretch of invalidity that actually PERSISTS past the bound
    //! must escalate).
    use super::safety::*;
    use super::types::*;
    use azos_drv_irqchip::clint;

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        super::envelope::serial()
    }

    fn reset() {
        estop_release(ReleaseAuthority::for_test());
        safety_set_robot_type(ROBOT_TYPE_WHEELED);
        test_reset_imu_incoherence();
        clint::clear_test_time();
    }

    /// **RED before the fix** (reproduced by reverting `check_common`'s new
    /// branch to its old `if !state.imu_valid { return SafetyResult::safe(); }`
    /// and re-running): this assertion failed with `violation: None` — a
    /// dead IMU 5 seconds in still read as nothing to check. See the agent
    /// report for the exact captured output.
    #[test]
    fn a_dead_imu_stops_the_robot_after_the_grace_period() {
        let _g = serial();
        reset();
        let s = SensorState::new(); // imu_valid == false, and stays false: no update_imu call.

        clint::set_test_time(1_000_000);
        assert_eq!(safety_check(&s).violation, SafetyViolation::None,
            "within the grace period, a missing sample is still just 'nothing to check yet'");

        clint::set_test_time(1_000_000 + IMU_INCOHERENT_AFTER_TICKS * 5); // 5 s further stale
        let r = safety_check(&s);
        assert_eq!(r.violation, SafetyViolation::SensorIncoherent,
            "a dead IMU must stop the robot once the grace period is exceeded");
        assert_eq!(r.action, SafetyAction::EmergencyStop);
    }

    /// A sample that arrives even once resets the grace period — recovery is
    /// immediate, not "wait out the same window again."
    #[test]
    fn one_valid_tick_resets_the_grace_period() {
        let _g = serial();
        reset();
        let mut s = SensorState::new();

        clint::set_test_time(1_000_000);
        let _ = safety_check(&s); // starts the invalid stretch.
        clint::set_test_time(1_000_000 + IMU_INCOHERENT_AFTER_TICKS - 1); // just under the bound.
        assert_eq!(safety_check(&s).violation, SafetyViolation::None);

        // A real sample arrives.
        s.imu_valid = true;
        s.accel_mg = [0, 0, 1000];
        assert_eq!(safety_check(&s).violation, SafetyViolation::None, "a valid sample is not itself a violation");

        // It goes stale again — the clock advances well past the bound from
        // BEFORE the recovery, but the invalid stretch only just restarted.
        s.imu_valid = false;
        clint::set_test_time(1_000_000 + IMU_INCOHERENT_AFTER_TICKS + 500);
        assert_eq!(safety_check(&s).violation, SafetyViolation::None,
            "the grace period must restart from the recovery, not resume counting from before it");
    }
}

// ---------------------------------------------------------------------------
// Subsumption arbiter (`domains/robot/behavior/src/arbiter.rs`) — the L0
// always-runs / always-applied / cannot-be-disabled claim.
//
// A claim scanner flagged the three "L0: always runs, cannot be disabled"
// comments (arbiter.rs, safety.rs, layers.rs) because `arbitrate()` calls
// `layer_emergency_stop` unconditionally but only RETURNS its result `if
// out.cmd.valid`. Read in isolation that gate looks like it could be a
// fail-open window. It is not: `SafetyAction::None` is the only variant
// `layer_emergency_stop` maps to an invalid `MotorOutput` (see
// `safety_check` and `layer_emergency_stop`), so `valid == false` means
// exactly "no violation fired," never "a violation fired but got dropped."
// The tests below exercise that gate directly against the real
// `arbitrate()`, both ways: a positive case where L0 must win, and a
// negative case where L0 must step aside. Asserting only the positive case
// would pass against a mutant that always returns L0's output regardless of
// `valid` — the exact shape of the scanner's concern — so the negative case
// is not optional here.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod arbitration {
    use super::arbiter::*;
    use super::safety::*;
    use super::types::*;

    /// `arbitrate` -> `layer_emergency_stop` -> `safety_check` reads the same
    /// process-wide statics (`ESTOP_ACTIVE`, `ROBOT_TYPE`, `GEOFENCE`) the
    /// `envelope` and `geofence` suites above exercise, so serialize against
    /// the same lock rather than a new one.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        super::envelope::serial()
    }

    /// Every input back to a known, permissive baseline, and every layer
    /// (including L0's own enable flag, which must be a no-op) reset to on.
    fn reset() {
        estop_release(ReleaseAuthority::for_test());
        safety_set_robot_type(ROBOT_TYPE_WHEELED);
        geofence_disable();
        super::offline::offline_deactivate();
        for l in 0..NUM_LAYERS {
            layer_set_enabled(l, true);
        }
        // See `geofence::reset()`'s identical line for why.
        super::safety::test_reset_imu_incoherence();
        // `camera_tx::CONTROL` is ALSO a process-wide static, shared with
        // `camera_tx_policy`'s tests, which do call `control_session_ready`.
        // A known "no brain connected" baseline is the precondition the
        // V1.5 tests below need, same reason every other flag here is
        // reset rather than inherited.
        super::camera_tx::control_session_ended();
    }

    /// A default `SensorState`: `imu_valid == false` short-circuits
    /// `check_common` to `safe()` (see `safety.rs::check_common`), and every
    /// other field defaults to a value `check_wheeled` treats as "nothing to
    /// check" (`battery_mv == 0`, `cam_dist_front == 0`, `gps_fix == 0`) — so
    /// this fixture is safety-clean by construction, not by luck. It also
    /// carries no remote action (`VlaAction::new().valid == false`), so L1
    /// and L2 cannot win either — the only layer left that CAN win on this
    /// fixture is L3 (`layer_explore`, unconditional). That makes it the
    /// sharpest possible fixture for the negative test below: if L0
    /// incorrectly wins here, there is no other explanation for it.
    fn clean_state() -> SensorState {
        SensorState::new()
    }

    /// **Positive half.** With a real violation (remote e-stop — the
    /// simplest one to force deterministically, and the one `safety_check`
    /// consults first), `arbitrate` must return L0's own command, applied,
    /// not merely computed.
    /// Wave 15: the RC manual override. The sticks outrank L1's steering, the
    /// brain (L2) and L3; L0 and L1's STOP outrank the sticks.
    #[test]
    fn rc_manual_outranks_autonomy_but_not_l0_or_an_obstacle_stop() {
        let _g = serial();
        reset();
        super::camera_tx::control_session_ready();
        let mut s = clean_state();
        s.rc_manual = MotorOutput::some(100, 100);
        let fwd = MlpResult { class: 0, valid: true };
        let out = arbitrate(&s, &fwd);
        assert_eq!((out.layer, out.cmd.speed_l, out.cmd.speed_r), (2, 100, 100),
            "the sticks beat L1's go_forward");
        let stop = MlpResult { class: 2, valid: true };
        let out = arbitrate(&s, &stop);
        assert_eq!((out.layer, out.cmd.speed_l, out.cmd.speed_r), (1, 0, 0),
            "an obstacle stop beats the sticks");
        estop_activate();
        let out = arbitrate(&s, &fwd);
        assert_eq!((out.layer, out.cmd.speed_l, out.cmd.speed_r), (0, 0, 0),
            "L0 beats the sticks");
        reset();
    }

    #[test]
    fn arbitrate_returns_l0_output_on_a_real_violation() {
        let _g = serial();
        reset();
        estop_activate();
        let out = arbitrate(&clean_state(), &MlpResult::none());
        assert_eq!(out.layer, 0, "a real violation must win as L0");
        assert!(out.cmd.valid, "L0's command must be APPLIED, not just computed");
        assert_eq!((out.cmd.speed_l, out.cmd.speed_r), (0, 0),
            "an e-stop must stop both motors");
    }

    /// **Negative half — the one a scanner-shaped mutant fails.** Same
    /// arbiter, same call to `layer_emergency_stop`, but nothing is wrong.
    /// A mutant that drops `if out.cmd.valid` and always returns L0's output
    /// passes the positive test above (L0 still "wins" when there IS a
    /// violation) but fails here: the robot would report `layer == 0` and a
    /// stopped/invalid command forever, even with nothing wrong, and would
    /// never reach L3. That is precisely "always runs" being true while
    /// "correctly applied" is false in the other direction — L0 usurping
    /// layers it has nothing to say about.
    ///
    /// L3 needs a connected brain now (V1.5, below), so this fixture
    /// simulates one being up — the fixture's OWN point (nothing wrong, and
    /// a lower layer gets to answer) is orthogonal to whether a brain has
    /// ever connected, and mixing the two into one fixture would make a
    /// future regression in either property invisible in the other's test.
    #[test]
    fn arbitrate_falls_through_to_lower_layers_when_l0_is_clean() {
        let _g = serial();
        reset();
        super::camera_tx::control_session_ready();
        let out = arbitrate(&clean_state(), &MlpResult::none());
        assert_ne!(out.layer, 0, "with no violation, L0 must not be the winner");
        assert_eq!(out.layer, 3,
            "L1 (no MLP result) and L2 (no remote action) are also invalid on this \
             fixture, so L3 (explore) is the only layer left to win once a brain is connected");
        assert!(out.cmd.valid, "the robot must still be able to move once a brain is present");
    }

    /// **U14-2 / owner decision 2026-09-26 (V1.5), flipping the bug this
    /// fixture used to assert.** Before this decision, THIS EXACT fixture —
    /// L0 clean, no MLP result, no remote action, and (unstated, because
    /// nothing gated on it) no brain ever connected — made `layer_explore`
    /// win with `(30, 30)`, and the test called that "the robot must still
    /// be able to move." That is U08-2's finding in one host test: a robot
    /// that has never had a brain connected drove forward from boot,
    /// uncommanded and (until Q1.3) unrecorded. `arbitrate` must now hold —
    /// no layer wins, `(0, 0)`/invalid — until `camera_tx::
    /// control_session().up` says a brain is actually there.
    #[test]
    fn no_brain_ever_connected_arbitrate_holds_not_explores() {
        let _g = serial();
        reset(); // includes `control_session_ended()`: no brain connected.
        assert!(!super::camera_tx::control_session().up, "precondition: no brain connected");
        let out = arbitrate(&clean_state(), &MlpResult::none());
        assert_ne!(out.layer, 3, "with no brain ever connected, L3 must not win");
        assert!(!out.cmd.valid, "the robot must hold — no command — not drive uncommanded");
    }

    /// "Cannot be disabled," checked as its own claim: the same knob that
    /// gates L1-L3 must be a documented no-op for index 0, and a violation
    /// must still be caught after an attempt to use it.
    #[test]
    fn layer_zero_ignores_layer_set_enabled() {
        let _g = serial();
        reset();
        layer_set_enabled(0, false);
        assert!(layer_is_enabled(0),
            "layer_set_enabled(0, false) must be a no-op");
        estop_activate();
        let out = arbitrate(&clean_state(), &MlpResult::none());
        assert_eq!(out.layer, 0,
            "a violation must still be caught after attempting to disable L0");
    }

    /// Disabling every layer BELOW L0 must not touch L0's own gating — proves
    /// L0 is not wired through the same `LAYER_ENABLED` array L1-L3 share,
    /// just guarded at index 0.
    #[test]
    fn disabling_every_other_layer_does_not_affect_l0() {
        let _g = serial();
        reset();
        for l in 1..NUM_LAYERS {
            layer_set_enabled(l, false);
        }
        estop_activate();
        let out = arbitrate(&clean_state(), &MlpResult::none());
        assert_eq!(out.layer, 0);
        assert!(out.cmd.valid);
    }
}

#[allow(dead_code, unused_imports)]
#[path = "../../../../domains/robot/behavior/src/auth_envelope.rs"]
mod auth;

#[allow(dead_code, unused_imports)]
#[path = "../../../../domains/robot/behavior/src/auth_envelope_core.rs"]
mod auth_envelope_core;

#[cfg(test)]
mod envelope_auth {
    use super::auth::*;

    // Scope note, because what is NOT here matters.
    //
    // `wrap` binds `DIR_TX` into the MAC and `unwrap` binds `DIR_RX`, so the
    // kernel **cannot produce a frame its own receiver will accept** — that
    // separation is the reflection defence and it is deliberate. The
    // consequence for a host suite is that the accept path and the replay
    // window cannot be exercised here: forging an RX frame needs the HMAC
    // over `DIR_RX`, and `hmac_sha256_precomputed` is private precisely so
    // nothing in the kernel can do that.
    //
    // So the accept path and anti-replay are covered only end-to-end, by the
    // `link auth accepts valid key` scenario. What is covered here is every
    // rejection, plus the direction separation itself — and one accept
    // through the unauthenticated legacy arm, so "refuses everything" cannot
    // masquerade as correct.

    /// The envelope keeps process-wide state: the link key and the replay
    /// high-water mark. Serialised for the same reason as the safety tests.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn keyed() {
        let key = [0x5Au8; KEY_BYTES];
        assert!(unsafe { init(&key) }, "init must accept a 32-byte key");
        assert!(is_authenticated());
    }

    /// **The kernel's own frame must not be accepted by the kernel.** `wrap`
    /// signs with DIR_TX and `unwrap` verifies DIR_RX, so a frame reflected
    /// back at the sender fails authentication. Without this an attacker
    /// echoes the kernel's own status frames at it and they authenticate.
    #[test]
    fn a_frame_the_kernel_wrapped_is_refused_by_its_own_receiver() {
        let _g = serial();
        keyed();
        let mut frame = [0u8; 256];
        let n = wrap(b"status", &mut frame);
        assert!(n >= ENVELOPE_OVERHEAD, "wrap must produce a full envelope");
        let mut out = [0u8; 256];
        assert!(unwrap(&frame[..n], &mut out).is_none(),
                "a TX-signed frame must not pass the RX direction check");
    }

    /// The two directions must bind different strings, or the check above is
    /// vacuous.
    #[test]
    fn the_two_directions_are_distinct() {
        assert_ne!(DIR_RX, DIR_TX, "direction separation requires two labels");
    }

    /// **V1.9 (coordinator decision, 2026-09-26): the pure `auth_envelope_
    /// core` module `userspace/services/brain_client` uses must be byte-for-byte wire
    /// compatible with the REAL kernel path** — proven both directions, with
    /// real HMAC-SHA-256, not a mocked comparison.
    #[test]
    fn auth_envelope_core_understands_a_frame_the_kernel_path_wrapped() {
        let _g = serial();
        keyed();
        let key = [0x5Au8; KEY_BYTES];
        let inner = b"status-frame-payload";
        let mut frame = [0u8; 256];
        let n = wrap(inner, &mut frame); // real kernel path: DIR_TX, its own nonce.
        assert!(n >= ENVELOPE_OVERHEAD, "wrap must produce a full envelope");

        let mut out = [0u8; 256];
        let (_nonce, len) = super::auth_envelope_core::verify_and_unwrap(
            &key, super::auth_envelope_core::DIR_TX, 0, &frame[..n], &mut out)
            .expect("the pure module must accept a frame the real kernel path wrapped");
        assert_eq!(&out[..len], inner, "and recover the same inner bytes");
    }

    #[test]
    fn a_frame_auth_envelope_core_wrapped_is_accepted_by_the_real_kernel_unwrap() {
        let _g = serial();
        keyed();
        let key = [0x5Au8; KEY_BYTES];
        let inner = b"actuator-frame";
        let mut frame = [0u8; 256];
        let n = super::auth_envelope_core::wrap(
            &key, super::auth_envelope_core::DIR_RX, 1, inner, &mut frame);
        assert!(n >= ENVELOPE_OVERHEAD);

        let mut out = [0u8; 256];
        let got = unwrap(&frame[..n], &mut out)
            .expect("the real kernel unwrap must accept a frame the pure module wrapped");
        assert_eq!(&out[..got], inner);
    }

    /// **Cross-language golden vector.** These exact bytes were produced by
    /// `tools/fake_brain.py`'s `wrap_envelope` (the Python peer `--wrap`
    /// uses against `brain_client`), captured 2026-09-26. If either side's
    /// byte layout ever drifts, this is the test that catches it — the two
    /// implementations are otherwise never run against each other.
    #[test]
    fn a_frame_fake_brain_py_wrapped_decodes_here() {
        let key = [0x5Au8; 32];
        let wrapped = hex_decode(
            "000000000000000177c579f7329261f0df14ff85a4df533f0d0042528007000002003c003c0053");
        let inner = hex_decode("42528007000002003c003c0053");
        let mut out = [0u8; 64];
        let (nonce, len) = super::auth_envelope_core::verify_and_unwrap(
            &key, super::auth_envelope_core::DIR_RX, 0, &wrapped, &mut out)
            .expect("fake_brain.py's wrapped bytes must verify here");
        assert_eq!(nonce, 1);
        assert_eq!(&out[..len], &inner[..]);
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// A forged frame (wrong key) must still be refused by the pure module —
    /// it is not merely "whatever the real path accepts, this also accepts."
    #[test]
    fn auth_envelope_core_refuses_a_forged_frame() {
        let _g = serial();
        keyed();
        let wrong_key = [0x00u8; KEY_BYTES];
        let inner = b"forged";
        let mut frame = [0u8; 256];
        let n = super::auth_envelope_core::wrap(
            &wrong_key, super::auth_envelope_core::DIR_TX, 1, inner, &mut frame);
        let key = [0x5Au8; KEY_BYTES];
        let mut out = [0u8; 256];
        assert!(super::auth_envelope_core::verify_and_unwrap(
            &key, super::auth_envelope_core::DIR_TX, 0, &frame[..n], &mut out).is_none(),
            "a frame signed under the wrong key must be refused");
    }

    /// **An accept case, so the rejections mean something.** With no key and
    /// enforcement off, the legacy arm passes bytes through unchanged; a
    /// receiver that refused everything would fail here.
    #[test]
    fn the_unauthenticated_legacy_arm_passes_bytes_through() {
        let _g = serial();
        let zero = [0u8; KEY_BYTES];
        unsafe { init(&zero) };            // all-zero key = not authenticated
        if is_authenticated() { return; }  // enforced build: arm absent by design
        let inner = b"legacy";
        let mut out = [0u8; 64];
        let n = unwrap(inner, &mut out).expect("legacy passthrough must accept");
        assert_eq!(&out[..n], inner);
    }

    /// **Any tampering must be refused, wherever it lands.** The MAC covers
    /// direction, nonce, length and payload, so a flipped bit in each region
    /// must fail — testing only the payload would pass on an implementation
    /// that authenticates the payload alone and lets the length be rewritten.
    #[test]
    fn a_flipped_bit_anywhere_is_refused() {
        let _g = serial();
        keyed();
        let mut frame = [0u8; 256];
        let n = wrap(b"cmd", &mut frame);
        for pos in [0usize, NONCE_BYTES, NONCE_BYTES + HMAC_BYTES, ENVELOPE_OVERHEAD] {
            let mut bad = frame;
            bad[pos] ^= 0x01;
            let mut out = [0u8; 256];
            assert!(unwrap(&bad[..n], &mut out).is_none(),
                    "a flipped bit at offset {pos} was accepted");
        }
    }

    /// A frame shorter than the fixed overhead, and one whose declared length
    /// runs past the buffer, must be refused rather than indexed. The length
    /// is two attacker-controlled bytes.
    #[test]
    fn short_and_overlong_frames_are_refused() {
        let _g = serial();
        keyed();
        let mut out = [0u8; 256];
        for n in 0..ENVELOPE_OVERHEAD {
            assert!(unwrap(&vec![0u8; n], &mut out).is_none(),
                    "{n} bytes is below the envelope overhead");
        }
        let mut frame = [0u8; 256];
        let n = wrap(b"cmd", &mut frame);
        frame[NONCE_BYTES + HMAC_BYTES]     = 0xFF;
        frame[NONCE_BYTES + HMAC_BYTES + 1] = 0xFF;
        assert!(unwrap(&frame[..n], &mut out).is_none(),
                "a length beyond the frame must be refused");
    }

    /// An output buffer too small must be refused, not truncated into: a
    /// partially-copied command is still a command.
    #[test]
    fn an_undersized_output_buffer_is_refused() {
        let _g = serial();
        keyed();
        let mut frame = [0u8; 256];
        let n = wrap(b"0123456789", &mut frame);
        let mut tiny = [0u8; 4];
        assert!(unwrap(&frame[..n], &mut tiny).is_none());
    }
}

// ---------------------------------------------------------------------------
// Flight recorder (`crates/core/actuation/src/logger.rs`; moved from
// `domains/robot/behavior/src/logger.rs` in wave 11).
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[path = "../../../../crates/core/actuation/src/logger.rs"]
mod logger;

/// The safety event codes, read off `logger.rs` itself.
#[cfg(test)]
mod safety_codes {
    const LOGGER: &str = include_str!("../../../../crates/core/actuation/src/logger.rs");

    /// Every `pub const SAFETY_*: u8` in the recorder, parsed. Panics on one it
    /// cannot parse, so a code written some other way is not skipped.
    fn codes() -> Vec<(&'static str, u8)> {
        LOGGER
            .lines()
            .filter(|l| l.starts_with("pub const SAFETY_"))
            .map(|l| {
                let rest = &l["pub const ".len()..];
                let (name, value) = rest
                    .split_once(": u8 = 0x")
                    .unwrap_or_else(|| panic!("unparsed safety code: {l}"));
                let hex = value.trim_end_matches(';');
                let v = u8::from_str_radix(hex, 16).unwrap_or_else(|_| panic!("unparsed value: {l}"));
                (name, v)
            })
            .collect()
    }

    /// Each code names one event: two codes with one number would make a record
    /// of one indistinguishable from a record of the other.
    ///
    /// **Canary.** Set `SAFETY_EXEC_REFUSED` to `0x0C`: the pair is reported.
    #[test]
    fn every_safety_code_names_one_event() {
        let codes = codes();
        assert!(codes.len() >= 13, "found only {codes:?}");
        for (i, (a, va)) in codes.iter().enumerate() {
            for (b, vb) in &codes[i + 1..] {
                assert_ne!(va, vb, "{a} and {b} share the code {va:#04x}");
            }
        }
    }

    /// The two codes the seccomp image profiles write, at the values the parse
    /// above read, so the parse is checked against the compiled constants.
    #[test]
    fn the_seccomp_codes_are_the_compiled_constants() {
        let codes = codes();
        let value = |n: &str| codes.iter().find(|(name, _)| *name == n).map(|(_, v)| *v);
        assert_eq!(value("SAFETY_SECCOMP_AUDIT"), Some(super::logger::SAFETY_SECCOMP_AUDIT));
        assert_eq!(value("SAFETY_EXEC_REFUSED"), Some(super::logger::SAFETY_EXEC_REFUSED));
        assert_eq!(value("SAFETY_CAP_DENIED_SUPPRESSED"), Some(super::logger::SAFETY_CAP_DENIED_SUPPRESSED));
    }

    /// The supervisor's four actions under `SAFETY_DRIVER_SUPERVISOR` are four
    /// numbers: an end under `restart = no` (wave 11) must not read back as a
    /// give-up, nor as a restart. Canary: give `SUP_ACTION_NO_RESTART` the
    /// value 2: red.
    #[test]
    fn the_supervisor_actions_are_distinct() {
        use super::logger::{
            SUP_ACTION_GAVE_UP, SUP_ACTION_NO_RESTART, SUP_ACTION_RESPAWN_FAILED, SUP_ACTION_RESTART,
        };
        let a = [SUP_ACTION_RESTART, SUP_ACTION_GAVE_UP, SUP_ACTION_RESPAWN_FAILED, SUP_ACTION_NO_RESTART];
        for (i, x) in a.iter().enumerate() {
            assert!(!a[i + 1..].contains(x), "supervisor action {x} names two events");
        }
    }
}

/// Host stand-in for the `LogStorage` seam the flight recorder writes
/// through (`crates/core/actuation/src/logger.rs`), not for `azos_fs` itself.
///
/// Before the dependency was inverted, this suite carried a whole separate
/// crate (`shims/fs`) that impersonated `azos_fs`'s types and seven
/// functions, aliased to the name `azos_fs` in `Cargo.toml` so that
/// `logger.rs`'s `use azos_fs::{...}` resolved to it. `LogStorage` is a
/// trait `logger.rs` defines itself now, so there is nothing external left
/// to alias — the implementation below is just a struct in this crate,
/// which is what "the seam is what makes the tests possible at all" (see
/// the `crates/net/tftp` inversion this mirrors) means in practice: one fewer
/// crate, one fewer `Cargo.toml` trick, for a smaller interface.
///
/// Kept as a recorder, not a `/dev/null` stub, for the same reason as
/// before: it can fail a write, or return a short one, which is what a real
/// FAT32 driver does and what the flight recorder has to survive.
#[cfg(test)]
mod log_storage_mock {
    use super::logger::{LogHandle, LogStorage, LogStorageError};
    use std::sync::Mutex;

    /// One file the logger created, kept whole.
    #[derive(Clone, Debug, Default)]
    pub struct MockFile {
        pub bytes: Vec<u8>,
        pub closed: bool,
        pub fsyncs: usize,
        /// `logger_analytics().safety_violations` as of the instant this
        /// file's `open()` call ran. Exists to pin call ORDER (see
        /// `the_wrap_notice_is_logged_before_the_truncating_open`): the wrap
        /// notice is logged through `log_safety_violation` -- which bumps
        /// this counter -- before `storage.open()` runs for the post-wrap
        /// file, so that file's snapshot must already show it. Ordering is
        /// only half the property; where the bytes land is pinned separately
        /// by `the_wrap_notice_lands_in_the_file_whose_ending_it_describes`.
        pub safety_violations_at_open: u32,
    }

    #[derive(Default)]
    pub struct Recorder {
        pub files: Vec<MockFile>,
        pub writes: usize,
        /// `open` refuses — `logger_init` (or a rotation) fails and the
        /// logger stays, or goes, inactive. Stands in for anything that can
        /// make a real mount/open fail; the recorder cannot and does not
        /// tell the difference.
        pub open_fails: bool,
        /// The Nth `write` (0-based) fails, writing nothing.
        pub fail_write_at: Option<usize>,
        /// The Nth `write` (0-based) writes only this many bytes and reports
        /// that count — the torn-write case.
        pub short_write_at: Option<(usize, usize)>,
        /// The `serial` argument of every `open()` call, in call order — so
        /// a test can pin WHICH serial `logger_init` opened, not just how
        /// many times it opened something. Added 2026-09-26 (U08-3): before
        /// then every session opened 0, 1, 2, ... from its own start, so the
        /// call-order index and the serial always agreed and nothing needed
        /// to tell them apart.
        pub opened_serials: Vec<u32>,
    }

    static REC: Mutex<Option<Recorder>> = Mutex::new(None);

    /// Start a fresh recording. Every test must call this first.
    pub fn reset() {
        *REC.lock().unwrap() = Some(Recorder::default());
    }

    pub fn with<R>(f: impl FnOnce(&mut Recorder) -> R) -> R {
        let mut g = REC.lock().unwrap();
        f(g.as_mut().expect("call log_storage_mock::reset() first"))
    }

    /// All bytes of the file at `index`, in write order.
    pub fn file_bytes(index: usize) -> Vec<u8> {
        with(|r| r.files.get(index).map(|f| f.bytes.clone()).unwrap_or_default())
    }

    pub fn file_count() -> usize {
        with(|r| r.files.len())
    }

    /// The `serial` argument of every `open()` call, in call order.
    pub fn opened_serials() -> Vec<u32> {
        with(|r| r.opened_serials.clone())
    }

    /// The one `LogStorage` under test. A unit struct: all state lives in
    /// `REC`, so this needs no fields and is trivially `Sync`.
    pub struct MockStorage;
    pub static STORAGE: MockStorage = MockStorage;

    impl LogStorage for MockStorage {
        fn open(&self, serial: u32) -> Result<LogHandle, LogStorageError> {
            let sv = super::logger::logger_analytics().safety_violations;
            with(|r| {
                r.opened_serials.push(serial);
                if r.open_fails {
                    return Err(LogStorageError::Unavailable);
                }
                r.files.push(MockFile { safety_violations_at_open: sv, ..Default::default() });
                Ok(LogHandle((r.files.len() - 1) as u32))
            })
        }

        fn write(&self, handle: LogHandle, buf: &[u8]) -> Result<usize, LogStorageError> {
            with(|r| {
                let n = r.writes;
                r.writes += 1;
                if r.fail_write_at == Some(n) {
                    return Err(LogStorageError::Io);
                }
                let take = match r.short_write_at {
                    Some((at, len)) if at == n => len.min(buf.len()),
                    _ => buf.len(),
                };
                let f = r.files.get_mut(handle.0 as usize)
                    .ok_or(LogStorageError::Unavailable)?;
                f.bytes.extend_from_slice(&buf[..take]);
                Ok(take)
            })
        }

        fn fsync(&self, handle: LogHandle) -> Result<(), LogStorageError> {
            with(|r| {
                let f = r.files.get_mut(handle.0 as usize)
                    .ok_or(LogStorageError::Unavailable)?;
                f.fsyncs += 1;
                Ok(())
            })
        }

        fn close(&self, handle: LogHandle) -> Result<(), LogStorageError> {
            with(|r| {
                let f = r.files.get_mut(handle.0 as usize)
                    .ok_or(LogStorageError::Unavailable)?;
                f.closed = true;
                Ok(())
            })
        }
    }
}

/// The motor-command watchdog's record (`SAFETY_RT_WATCHDOG`, wave 14): the
/// transitions policy, and the record through the recorder and back.
#[cfg(test)]
mod rt_watchdog_records {
    use super::logger::*;
    use super::log_storage_mock as fsmock;

    const WINDOW: u64 = 60 * 10_000_000; // 60 s at QEMU's 10 MHz

    /// The first SAFE STOP and the first clear are reported; a thousand flaps
    /// after them are one count at the window's end, and nothing before it.
    /// A quiet window re-arms the first two. Never more than three reports
    /// a window. Canary (by hand): `stop()` always `Some` turns it red.
    #[test]
    fn transitions_only_then_one_count_per_window() {
        let mut r = RtWatchdogReports::new(1_000, WINDOW);
        assert_eq!(r.stop(), Some((RTWD_ACTION_STOP, 0)));
        assert_eq!(r.clear(), Some((RTWD_ACTION_CLEAR, 0)));
        let mut reported = 2;
        for _ in 0..500 {
            reported += r.stop().is_some() as u32;
            reported += r.clear().is_some() as u32;
        }
        assert_eq!(reported, 2, "a flap after the first two was reported");
        assert_eq!(r.tick(1_000 + WINDOW - 1, true), None, "the window has not ended");
        assert_eq!(r.tick(1_000 + WINDOW, true),
                   Some((RTWD_ACTION_REPEATS, rtwd_repeats_detail(1_000, true))));
        // Still armed off: the window above was not quiet.
        assert_eq!(r.stop(), None);
        assert_eq!(r.tick(1_000 + 2 * WINDOW, false),
                   Some((RTWD_ACTION_REPEATS, rtwd_repeats_detail(1, false))));
        // A quiet window: no record, and the first transitions report again.
        assert_eq!(r.tick(1_000 + 3 * WINDOW, false), None);
        assert_eq!(r.stop(), Some((RTWD_ACTION_STOP, 0)));
        assert_eq!(r.clear(), Some((RTWD_ACTION_CLEAR, 0)));
    }

    /// The repeats detail keeps the count and the end state apart, and a
    /// count past 31 bits saturates instead of setting the state bit.
    #[test]
    fn the_repeats_detail_round_trips() {
        for (n, stopped) in [(0, false), (43, true), (43, false), (0x7FFF_FFFF, true)] {
            assert_eq!(rtwd_repeats_from_detail(rtwd_repeats_detail(n, stopped)), (n, stopped));
        }
        assert_eq!(rtwd_repeats_from_detail(rtwd_repeats_detail(u32::MAX, false)), (0x7FFF_FFFF, false));
    }

    /// Through the recorder: the durable stop is on the storage when the
    /// call returns, the clear and the count follow at the next flush, and
    /// each decodes back to its code, action and detail.
    #[test]
    fn the_records_reach_storage_and_decode() {
        let _g = super::flight_recorder::begin(0);
        logger_init().expect("mount succeeds");
        log_safety_violation_durable(SAFETY_RT_WATCHDOG, RTWD_ACTION_STOP, 0)
            .expect("durable flush reaches the seam");
        assert_eq!(fsmock::file_bytes(0).len(), LOG_FILE_HEADER_BYTES + LOG_RECORD_SIZE,
                   "the stop record was not on the storage when the call returned");
        log_safety_violation(SAFETY_RT_WATCHDOG, RTWD_ACTION_CLEAR, 0);
        log_safety_violation(SAFETY_RT_WATCHDOG, RTWD_ACTION_REPEATS, rtwd_repeats_detail(43, true));
        logger_flush().expect("flush");
        let bytes = fsmock::file_bytes(0);
        let body = &bytes[LOG_FILE_HEADER_BYTES..];
        assert_eq!(body.len(), 3 * LOG_RECORD_SIZE);
        let want = [(RTWD_ACTION_STOP, 0u32), (RTWD_ACTION_CLEAR, 0),
                    (RTWD_ACTION_REPEATS, rtwd_repeats_detail(43, true))];
        for (i, (action, detail)) in want.iter().enumerate() {
            let raw: &[u8; LOG_RECORD_SIZE] =
                body[i * LOG_RECORD_SIZE..(i + 1) * LOG_RECORD_SIZE].try_into().unwrap();
            let rec = LogRecord::decode(raw);
            let mut again = [0u8; LOG_RECORD_SIZE];
            rec.encode(&mut again);
            assert_eq!(&again, raw, "record {i} does not re-encode to its bytes");
            assert_eq!(rec.kind, LOG_EVT_SAFETY_VIOLATION);
            assert_eq!((rec.payload[0], rec.payload[1]), (SAFETY_RT_WATCHDOG, *action));
            let d = u32::from_le_bytes(rec.payload[4..8].try_into().unwrap());
            assert_eq!(d, *detail);
        }
        assert_eq!(rtwd_repeats_from_detail(rtwd_repeats_detail(43, true)), (43, true));
        logger_shutdown();
    }
}

#[cfg(test)]
mod flight_recorder {
    use super::logger::*;
    use super::log_storage_mock as fsmock;

    /// The logger's state is process-wide (`LOG_RING`, `LOG_ACTIVE`, the
    /// serial counter, the analytics atomics, and now the registered
    /// `LogStorage` pointer) and so is the mock's recorder. One lock for
    /// both, because they are one state machine: a second lock over the
    /// same globals serializes nothing, which this project has already paid
    /// for once in `fs-tests`.
    pub(crate) static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Fresh recorder, fresh logger, pinned clock.
    pub(crate) fn begin(ts: u64) -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());

        // `LOG_SERIAL` is a process-wide monotonic counter with no public
        // reset, so once any test (`the_wrap_notice_is_logged_before_the_
        // truncating_open`) forces it past `LOG_SERIAL_WRAP` via
        // `set_serial_for_test`, it STAYS past the wrap point for the rest
        // of the process -- there is nothing else that ever moves it back
        // down. Every `logger_init()` from that point on -- including the
        // drain cycle two lines down, and every later test's own call --
        // takes `open_log_file`'s wrap branch and bumps
        // `LOG_SAFETY_COUNT` by one (the cold-boot corner case that
        // function's own comment documents: `LOG_ACTIVE` is still false at
        // that push, so the ring never sees it, but the counter does).
        // Harmless to a test that does not check the exact count, and a
        // silent off-by-one to one that does -- which test that turns out
        // to be depends on scheduling order between it and the wrap test
        // under parallel execution, so it is exactly the kind of failure
        // that looks like a regression in whichever test happens to run
        // downstream. Reset here, before anything else touches the logger,
        // so every test starts from the same known serial regardless of
        // what an earlier one did to this global.
        set_serial_for_test(0);

        // Registering the storage is idempotent (it just overwrites the same
        // pointer) so it is safe to do on every `begin()`, not only the first.
        logger_set_storage(&fsmock::STORAGE);

        // Drain whatever the previous test left, into a throwaway recorder.
        //
        // This does NOT just call `logger_shutdown()`: that early-returns when
        // the logger is already inactive, so records left in the ring by a
        // test that shut down would survive into the next one. The ring is a
        // process-wide static with no public clear, so the only way to empty
        // it through the real API is to bring the logger up on a scratch
        // volume and flush.
        fsmock::reset();
        let _ = logger_init();
        let _ = logger_flush();
        logger_shutdown();

        // State the precondition rather than inheriting it. Without this a
        // bug in `logger_flush` shows up as five confusing failures in
        // unrelated tests instead of one that names the cause.
        assert_eq!(
            logger_ring_len(), 0,
            "the previous test left records in the ring and they could not be drained; \
             every assertion after this point would be reading them",
        );

        fsmock::reset();
        azos_drv_irqchip::clint::set_test_time(ts);
        logger_analytics_reset();
        // Same reasoning as the ring above, for the one other piece of
        // process-wide state a test can move: `LOG_SERIAL`. The two wrap
        // tests seed it past `LOG_SERIAL_WRAP` and nothing puts it back, so
        // without this every test that ran after one of them would have its
        // `logger_init` quietly prepend a SAFETY_LOG_WRAPPED record — which
        // only shows up as a wrong record count, in whichever test the
        // runner happened to schedule next.
        set_serial_for_test(0);
        g
    }

    fn start() -> std::sync::MutexGuard<'static, ()> {
        begin(0x1122_3344_5566_7788)
    }

    /// Records as a decoder sees them: fixed 32-byte frames after the header.
    pub(crate) fn decode_file(index: usize) -> Vec<LogRecord> {
        let bytes = fsmock::file_bytes(index);
        assert!(bytes.len() >= LOG_FILE_HEADER_BYTES, "file is missing its header");
        let body = &bytes[LOG_FILE_HEADER_BYTES..];
        assert_eq!(
            body.len() % LOG_RECORD_SIZE, 0,
            "a decoder reading fixed {LOG_RECORD_SIZE}-byte frames cannot resynchronise: \
             {} body bytes is not a whole number of records",
            body.len(),
        );
        body.chunks(LOG_RECORD_SIZE)
            .map(|c| {
                let mut b = [0u8; LOG_RECORD_SIZE];
                b.copy_from_slice(c);
                LogRecord::decode(&b)
            })
            .collect()
    }

    #[test]
    fn a_round_trip_puts_every_record_on_disk_in_order() {
        let _g = start();
        logger_init().expect("mount succeeds");
        for i in 0..10u16 {
            log_skill_start(i);
        }
        assert_eq!(logger_flush().unwrap(), 10);
        let recs = decode_file(0);
        assert_eq!(recs.len(), 10);
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(r.kind, LOG_EVT_SKILL_START);
            assert_eq!(u16::from_le_bytes([r.payload[0], r.payload[1]]), i as u16);
        }
        logger_shutdown();
    }

    /// **Defect 1.** `logger_flush` drains the ring into a local batch before
    /// it writes. If the write fails, those records are off the ring and were
    /// never on disk — only a counter moved. For a flight recorder the
    /// records around a failure are exactly the ones worth keeping.
    #[test]
    fn a_failed_flush_does_not_destroy_the_records_it_could_not_write() {
        let _g = start();
        logger_init().expect("mount succeeds");
        for i in 0..5u16 {
            log_skill_start(i);
        }
        // The header write was write #0, so the first flush is write #1.
        fsmock::with(|r| r.fail_write_at = Some(1));
        assert!(logger_flush().is_err());
        assert_eq!(
            logger_ring_len(), 5,
            "the 5 records the write could not take must still be in the ring, \
             ready for the next flush",
        );
        // And they must actually make it out once the device recovers.
        fsmock::with(|r| r.fail_write_at = None);
        assert_eq!(logger_flush().unwrap(), 5);
        assert_eq!(decode_file(0).len(), 5);
        logger_shutdown();
    }

    /// **Defect 2.** `fat32_write` returns a count and nothing promises it
    /// equals `buf.len()`. The old code added that count to `bytes_written`
    /// and moved on, leaving a torn 32-byte record in the file — after which
    /// every record was misframed for a decoder reading fixed frames.
    ///
    /// A short write is a transient, so the fix writes the remainder. Nothing
    /// is torn and nothing is lost.
    #[test]
    fn a_short_write_is_completed_rather_than_leaving_a_torn_record() {
        let _g = start();
        logger_init().expect("mount succeeds");
        for i in 0..4u16 {
            log_skill_start(i);
        }
        // Take 2.5 records' worth: 80 of the 128 bytes asked for.
        fsmock::with(|r| r.short_write_at = Some((1, 80)));
        assert_eq!(logger_flush().unwrap(), 4, "the retry completes the chunk");

        // `decode_file` asserts the body is a whole number of records, which
        // is the property a fixed-frame decoder depends on.
        let recs = decode_file(0);
        assert_eq!(recs.len(), 4);
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(
                u16::from_le_bytes([r.payload[0], r.payload[1]]), i as u16,
                "record {i} is misframed",
            );
        }
        logger_shutdown();
    }

    /// A device that stops making progress mid-record is the one case the
    /// torn tail cannot be repaired. It must not be silent, and it must not
    /// contaminate what comes next: the flush reports the error, counts it,
    /// and rotates so the partial record sits at EOF of a closed file while
    /// the next file starts on a record boundary.
    #[test]
    fn a_device_that_stalls_mid_record_rotates_instead_of_corrupting_the_rest() {
        let _g = start();
        logger_init().expect("mount succeeds");
        for i in 0..4u16 {
            log_skill_start(i);
        }
        // 80 bytes, then the retry takes nothing at all.
        fsmock::with(|r| {
            r.short_write_at = Some((1, 80));
            r.fail_write_at = Some(2);
        });
        assert!(logger_flush().is_err(), "a stalled device must be reported");
        assert_eq!(logger_analytics().flush_errors, 1);

        // The two whole records left the ring; the two that did not are kept.
        assert_eq!(logger_ring_len(), 2, "unwritten records stay on the ring");

        // File 0 keeps its torn tail — but it is closed, and a new file was
        // opened, so nothing after this point is misframed.
        assert_eq!(fsmock::file_count(), 2, "the damaged file was rotated away");
        assert!(fsmock::with(|r| r.files[0].closed));
        assert_eq!(
            fsmock::file_bytes(1).len(), LOG_FILE_HEADER_BYTES,
            "the fresh file holds just its header, so it starts on a record boundary",
        );
        logger_shutdown();
    }

    /// **Defect 3.** `logger_flush` held a 128-record batch (4 KiB) *and* a
    /// 4 KiB encode buffer in one frame, on a 16 KiB kernel stack
    /// (`CONFIG_KERNEL_STACK_SIZE_KB=16`), with the FAT32 write path and its
    /// own sector buffering underneath it.
    ///
    /// Asserted on the constant rather than by eyeballing the source, so
    /// raising the batch size trips here instead of on the board.
    #[test]
    fn the_flush_buffers_do_not_eat_the_kernel_stack() {
        let batch = LOG_FLUSH_BATCH_MAX * core::mem::size_of::<LogRecord>();
        let encode = LOG_FLUSH_BATCH_MAX * LOG_RECORD_SIZE;
        assert!(
            batch + encode <= 2048,
            "logger_flush would hold {} bytes of buffers in one frame; the kernel \
             stack is 16 KiB and FAT32 buffers sectors below this call",
            batch + encode,
        );
    }

    /// **Synchronous durability.** `log_safety_violation_durable` (e3245cb)
    /// exists because an e-stop is the event most likely to be followed
    /// within milliseconds by a reset -- half a second in the ring, waiting
    /// for the watchdog's cadence, means losing the record to the incident
    /// it describes. That only holds if the write actually reaches the
    /// storage seam before the call returns, not merely before some later
    /// flush. Pinned against the plain (non-durable) path, which must NOT
    /// reach the seam on its own.
    #[test]
    fn log_safety_violation_durable_reaches_storage_before_returning() {
        let _g = start();
        logger_init().expect("mount succeeds");

        // The plain path only queues; nothing but a future flush moves it.
        log_safety_violation(SAFETY_CAP_DENIED, 0, 0);
        assert_eq!(
            fsmock::file_bytes(0).len(), LOG_FILE_HEADER_BYTES,
            "a non-durable safety event must not reach the seam on its own",
        );

        // The durable path must -- by the time this call returns, not after
        // some later flush this test never makes.
        log_safety_violation_durable(SAFETY_ESTOP, 2, 0xE570_0000)
            .expect("durable flush reaches the seam");
        assert_eq!(
            fsmock::file_bytes(0).len(),
            LOG_FILE_HEADER_BYTES + 2 * LOG_RECORD_SIZE,
            "both the earlier queued event and the e-stop record must be on \
             the seam by the time log_safety_violation_durable returns",
        );
        logger_shutdown();
    }

    /// **Lock-order canary.** `logger_flush` takes `LOG_FILE` then `LOG_RING`
    /// (nested, see its own comment); `push_event` -- the only path into the
    /// ring outside of a flush -- takes `LOG_RING` alone. If a future edit
    /// ever made some path acquire `LOG_RING` first and then reach for
    /// `LOG_FILE`, that is the AB-BA shape: one thread holding FILE and
    /// wanting RING, another holding RING and wanting FILE, both wait
    /// forever. `panic = "abort"` on this kernel makes that a wedged flight
    /// recorder taking the board down with it, so this runs the real
    /// contention instead of trusting the ordering by inspection alone.
    ///
    /// Since wave 15 the ring takes no lock (producers claim slots with a
    /// CAS) and `LOG_FILE` is the recorder's own non-PI flush lock, whose
    /// waiters yield the OS thread here (`cap_test_sync`'s `WaitQueue`): a
    /// hang would still be a lock bug, and this test still bounds it. A watchdog thread bounds that: if the workers below
    /// have not finished within 5 s of real contention, it reports the hang
    /// and aborts the process outright, rather than letting one deadlocked
    /// test wedge the rest of the suite behind a shared static the way a
    /// real inversion would wedge the board.
    #[test]
    fn concurrent_flush_and_push_never_invert_the_file_ring_order() {
        let _g = start();
        logger_init().expect("mount succeeds");

        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watchdog_done = done.clone();
        let watchdog = std::thread::spawn(move || {
            for _ in 0..100 {
                std::thread::sleep(std::time::Duration::from_millis(50));
                if watchdog_done.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
            }
            eprintln!(
                "DEADLOCK: logger_flush (FILE then RING) and push_event (RING \
                 alone) did not finish within 5s of concurrent contention -- \
                 the FILE/RING lock order documented in logger.rs's \
                 logger_flush has inverted somewhere",
            );
            std::process::exit(97);
        });

        const ITERS: usize = 4000;

        let flusher = std::thread::spawn(|| {
            for _ in 0..ITERS {
                let _ = logger_flush();
            }
        });
        let pusher_a = std::thread::spawn(|| {
            for i in 0..ITERS {
                log_skill_start(i as u16);
            }
        });
        let pusher_b = std::thread::spawn(|| {
            for i in 0..ITERS {
                log_mode_change((i % 4) as u8, ((i + 1) % 4) as u8);
            }
        });
        // A third caller of both locks, and the only one that takes them
        // sequentially (RING via `push_event`, released, then FILE via
        // `logger_flush`) rather than in one nested call -- not covered by
        // the two workers above.
        let durable = std::thread::spawn(|| {
            for _ in 0..(ITERS / 4) {
                let _ = log_safety_violation_durable(SAFETY_CAP_DENIED, 0, 0);
            }
        });

        flusher.join().expect("flusher thread panicked");
        pusher_a.join().expect("pusher_a thread panicked");
        pusher_b.join().expect("pusher_b thread panicked");
        durable.join().expect("durable thread panicked");

        done.store(true, std::sync::atomic::Ordering::SeqCst);
        watchdog.join().expect("watchdog thread panicked");

        // Drain whatever the workers left so the next test's precondition
        // (`logger_ring_len() == 0` in `begin()`) holds.
        let _ = logger_flush();
        logger_shutdown();
    }
}

/// Wave 15, owner rule: an RT task never does block I/O. The ring is
/// lock-free and the RT caller's flush is handed to the log flusher.
#[cfg(test)]
mod flight_recorder_rt {
    use super::logger::*;
    use super::flight_recorder::{begin, decode_file};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn rt_yes() -> bool { true }
    fn rt_no() -> bool { false }

    /// An RT caller's durable record is NOT written by the caller: it gets
    /// `Deferred`, the medium is untouched, the record waits on the ring,
    /// and one flusher pass puts it on the medium.
    #[test]
    fn an_rt_durable_record_is_written_by_the_flusher_not_the_caller() {
        let _g = begin(0x0A0B_0C0D);
        logger_init().expect("mount succeeds");
        let before = decode_file(0).len();
        logger_set_rt_probe(rt_yes);
        let r = log_safety_violation_durable(SAFETY_ESTOP, 9, 0xE57);
        logger_set_rt_probe(rt_no);
        assert_eq!(r, Err(LogStorageError::Deferred), "an RT caller must not flush");
        assert_eq!(decode_file(0).len(), before, "the RT caller wrote the medium");
        assert_eq!(logger_ring_len(), 1, "the record waits on the ring");
        logger_flusher_pass();
        let recs = decode_file(0);
        assert_eq!(recs.len(), before + 1, "one flusher pass writes it");
        let last = recs.last().unwrap();
        assert_eq!((last.kind, last.payload[0], last.payload[1]), (LOG_EVT_SAFETY_VIOLATION, SAFETY_ESTOP, 9));
        assert_eq!(logger_ring_len(), 0);
        logger_shutdown();
    }

    static JOB_RAN: AtomicUsize = AtomicUsize::new(0);
    fn job() { JOB_RAN.fetch_add(1, Ordering::SeqCst); }

    /// A deferred I/O job runs on the flusher's next pass, once.
    #[test]
    fn a_deferred_io_job_runs_once_on_the_flusher() {
        let _g = begin(0x0A0B_0C0E);
        let n = JOB_RAN.load(Ordering::SeqCst);
        assert!(logger_defer_io(job));
        assert_eq!(JOB_RAN.load(Ordering::SeqCst), n, "the poster ran its own job");
        logger_flusher_pass();
        logger_flusher_pass();
        assert_eq!(JOB_RAN.load(Ordering::SeqCst), n + 1);
    }

    /// Four producers push past capacity while a consumer flushes: no record
    /// is torn, none is written twice, each producer's records stay in
    /// order, and every record pushed is on the medium or counted dropped.
    #[test]
    fn concurrent_producers_past_capacity_tear_nothing_and_lose_nothing_uncounted() {
        let _g = begin(0x0A0B_0C0F);
        logger_init().expect("mount succeeds");
        let dropped0 = logger_analytics().events_dropped;
        const PER: u32 = 4000;
        const THREADS: u32 = 4;
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let s2 = stop.clone();
        let flusher = std::thread::spawn(move || {
            while !s2.load(Ordering::SeqCst) { let _ = logger_flush(); }
        });
        let pushers: Vec<_> = (0..THREADS).map(|t| std::thread::spawn(move || {
            for i in 0..PER {
                let x = ((t << 24) | i) as i32;
                log_waypoint(x, !x, (x as u16) ^ 0x5A5A, 0x77);
            }
        })).collect();
        for p in pushers { p.join().unwrap(); }
        stop.store(true, Ordering::SeqCst);
        flusher.join().unwrap();
        let _ = logger_flush();
        assert_eq!(logger_ring_len(), 0);
        let mut last = [None::<u32>; THREADS as usize];
        let mut written = 0u32;
        for r in decode_file(0).iter().filter(|r| r.kind == LOG_EVT_WAYPOINT) {
            let x = i32::from_le_bytes(r.payload[0..4].try_into().unwrap());
            let y = i32::from_le_bytes(r.payload[4..8].try_into().unwrap());
            let idx = u16::from_le_bytes([r.payload[8], r.payload[9]]);
            assert!(y == !x && idx == (x as u16) ^ 0x5A5A && r.payload[10] == 0x77, "torn record x={x:#x}");
            let (t, i) = ((x as u32) >> 24, (x as u32) & 0xFF_FFFF);
            if let Some(prev) = last[t as usize] {
                assert!(i > prev, "thread {t}: record {i} after {prev} (duplicate or reordered)");
            }
            last[t as usize] = Some(i);
            written += 1;
        }
        let dropped = logger_analytics().events_dropped - dropped0;
        assert!(written <= THREADS * PER);
        assert!(written + dropped >= THREADS * PER,
            "{} pushed, {written} written, {dropped} dropped: a loss went uncounted", THREADS * PER);
        logger_shutdown();
    }

    /// The interleaving behind `concurrent_producers_past_capacity_…`'s
    /// rare "a loss went uncounted" (2 of 40 suite runs before the fix),
    /// taken deterministically: producer A finds the ring full and evicts
    /// the oldest record, and before A reloads the head another producer
    /// (the hook's nested push) claims the slot A freed. A must evict again
    /// for the next position: two records gone, and both must be counted.
    /// Before the fix `ring_push` returned a `bool` and this counted 1.
    ///
    /// Other modules' tests (safety, payload, e-stop) log through the same
    /// recorder under their own locks: a foreign flush can drain the ring
    /// or a foreign push evict, inside this window. An attempt that saw the
    /// ring not full is retried; the broken count is 1 on every attempt.
    #[test]
    fn an_eviction_whose_slot_is_stolen_is_counted_twice() {
        let _g = begin(0x0A0B_0C10);
        logger_init().expect("mount succeeds");
        fn steal() { log_waypoint(-2, 1, 2, 0x22); }
        let mut seen = Vec::new();
        for _ in 0..10 {
            for i in 0..LOG_RING_CAPACITY as i32 {
                log_waypoint(i, !i, 1, 0x11);
            }
            if logger_ring_len() != LOG_RING_CAPACITY {
                continue;
            }
            let d0 = logger_analytics().events_dropped;
            set_ring_evict_hook_for_test(Some(steal));
            log_waypoint(-3, 2, 3, 0x33);
            // Disarmed whether it ran or not: never a later test's push.
            set_ring_evict_hook_for_test(None);
            let evicted = logger_analytics().events_dropped - d0;
            seen.push(evicted);
            if evicted == 2 && logger_ring_len() == LOG_RING_CAPACITY {
                let _ = logger_flush();
                let marks: Vec<u8> = decode_file(0).iter()
                    .filter(|r| r.kind == LOG_EVT_WAYPOINT).map(|r| r.payload[10]).collect();
                assert_eq!(&marks[marks.len() - 2..], &[0x22, 0x33], "the thief's record, then A's");
                logger_shutdown();
                return;
            }
        }
        let _ = logger_flush();
        logger_shutdown();
        panic!("two pushes into a full ring evicted two records; counted per attempt: {seen:?}");
    }

    /// Stress, no consumer of its own: four producers into a saturated
    /// ring, so nearly every push evicts and the stolen-slot window above
    /// opens constantly (the bool count lost about half of them). Every
    /// record pushed is on the medium or counted dropped. `>=`, as in the
    /// test above it: a foreign test's push or flush in the same window
    /// adds to the right side, never takes from it.
    #[test]
    fn a_saturated_ring_counts_every_eviction_under_contention() {
        let _g = begin(0x0A0B_0C11);
        logger_init().expect("mount succeeds");
        const PER: u32 = 20_000;
        const THREADS: u32 = 4;
        const MARK: u8 = 0x44;
        let d0 = logger_analytics().events_dropped as u64;
        let go = std::sync::Arc::new(std::sync::Barrier::new(THREADS as usize));
        let pushers: Vec<_> = (0..THREADS).map(|t| {
            let go = go.clone();
            std::thread::spawn(move || {
                go.wait();
                for i in 0..PER {
                    log_waypoint(((t << 24) | i) as i32, 0, 0, MARK);
                }
            })
        }).collect();
        for p in pushers { p.join().unwrap(); }
        let _ = logger_flush();
        assert_eq!(logger_ring_len(), 0);
        let dropped = logger_analytics().events_dropped as u64 - d0;
        let written = decode_file(0).iter()
            .filter(|r| r.kind == LOG_EVT_WAYPOINT && r.payload[10] == MARK).count() as u64;
        let pushed = (THREADS * PER) as u64;
        logger_shutdown();
        assert!(written + dropped >= pushed,
            "{pushed} pushed, {written} written, {dropped} dropped: a loss went uncounted");
    }
}

#[cfg(test)]
mod flight_recorder_format {
    use super::logger::*;
    use super::log_storage_mock as fsmock;

    /// Same globals as `flight_recorder`, so the same lock. Rust runs tests
    /// from different modules on the same threads, and two locks over one
    /// state machine serialize nothing.

    fn start() -> std::sync::MutexGuard<'static, ()> {
        super::flight_recorder::begin(0x0102_0304_0506_0708)
    }

    /// The on-disk header a decoder keys off. Pinned byte by byte: magic,
    /// little-endian version, the reserved u16, and the creation timestamp.
    #[test]
    fn the_file_header_is_the_documented_16_bytes() {
        let _g = start();
        logger_init().expect("mount succeeds");
        let bytes = fsmock::file_bytes(0);
        assert_eq!(bytes.len(), LOG_FILE_HEADER_BYTES);
        assert_eq!(&bytes[0..4], LOG_FILE_MAGIC, "magic must be RBL1");
        assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), LOG_FILE_VERSION);
        assert_eq!(u16::from_le_bytes([bytes[6], bytes[7]]), 0, "reserved u16");
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&bytes[8..16]);
        assert_eq!(u64::from_le_bytes(ts), 0x0102_0304_0506_0708);
        logger_shutdown();
    }

    /// The record layout the header comment promises:
    ///   [ts u64 LE] [kind u8] [flags u8] [_pad u16] [payload 20B]
    #[test]
    fn a_record_is_the_documented_32_bytes() {
        let mut payload = [0u8; LOG_PAYLOAD_BYTES];
        for (i, b) in payload.iter_mut().enumerate() { *b = i as u8 + 1; }
        let rec = LogRecord { ts: 0xDEAD_BEEF_1234_5678, kind: 0x42, flags: 0x99, payload };
        let mut buf = [0u8; LOG_RECORD_SIZE];
        rec.encode(&mut buf);
        assert_eq!(&buf[0..8], &0xDEAD_BEEF_1234_5678u64.to_le_bytes());
        assert_eq!(buf[8], 0x42);
        assert_eq!(buf[9], 0x99);
        assert_eq!(&buf[10..12], &[0, 0], "the pad must be written, not left stale");
        assert_eq!(&buf[12..32], &payload);

        let back = LogRecord::decode(&buf);
        assert_eq!(back.ts, rec.ts);
        assert_eq!(back.kind, rec.kind);
        assert_eq!(back.flags, rec.flags);
        assert_eq!(back.payload, rec.payload);
    }

    /// `log_error` writes `subsystem` at 0, `error_code` at 1..3, then skips
    /// byte 3 and puts `detail` at 4..8. The hole is alignment padding, not a
    /// bug — pinned so a decoder written against this layout stays right and
    /// so the gap is not quietly reused.
    #[test]
    fn log_error_leaves_byte_three_as_a_hole() {
        let _g = start();
        logger_init().expect("mount succeeds");
        log_error(0x7A, 0xBEEF, 0xDEAD_C0DE);
        logger_flush().unwrap();
        let bytes = fsmock::file_bytes(0);
        let mut rec = [0u8; LOG_RECORD_SIZE];
        rec.copy_from_slice(&bytes[LOG_FILE_HEADER_BYTES..LOG_FILE_HEADER_BYTES + LOG_RECORD_SIZE]);
        let r = LogRecord::decode(&rec);
        assert_eq!(r.kind, LOG_EVT_ERROR);
        assert_eq!(r.payload[0], 0x7A);
        assert_eq!(u16::from_le_bytes([r.payload[1], r.payload[2]]), 0xBEEF);
        assert_eq!(r.payload[3], 0, "byte 3 is padding between the code and the detail");
        let mut d = [0u8; 4];
        d.copy_from_slice(&r.payload[4..8]);
        assert_eq!(u32::from_le_bytes(d), 0xDEAD_C0DE);
        logger_shutdown();
    }

    /// Every event encoder writes its arguments where the format says.
    #[test]
    fn each_event_encoder_lands_its_fields_where_the_format_says() {
        let _g = start();
        logger_init().expect("mount succeeds");
        log_sensor_snapshot(0x1234, -300, 0x0000_ABCD, -12345);
        log_waypoint(-1000, 2000, 7, 0x5A);
        log_skill_end(0x0BAD, 0x33);
        logger_flush().unwrap();

        let bytes = fsmock::file_bytes(0);
        let body = &bytes[LOG_FILE_HEADER_BYTES..];
        let rec = |i: usize| {
            let mut b = [0u8; LOG_RECORD_SIZE];
            b.copy_from_slice(&body[i * LOG_RECORD_SIZE..(i + 1) * LOG_RECORD_SIZE]);
            LogRecord::decode(&b)
        };

        let s = rec(0);
        assert_eq!(s.kind, LOG_EVT_SENSOR_SNAPSHOT);
        assert_eq!(u16::from_le_bytes([s.payload[0], s.payload[1]]), 0x1234);
        assert_eq!(i16::from_le_bytes([s.payload[2], s.payload[3]]), -300);
        assert_eq!(
            u32::from_le_bytes([s.payload[4], s.payload[5], s.payload[6], s.payload[7]]),
            0x0000_ABCD,
        );
        assert_eq!(
            i32::from_le_bytes([s.payload[8], s.payload[9], s.payload[10], s.payload[11]]),
            -12345,
        );

        let w = rec(1);
        assert_eq!(w.kind, LOG_EVT_WAYPOINT);
        assert_eq!(
            i32::from_le_bytes([w.payload[0], w.payload[1], w.payload[2], w.payload[3]]),
            -1000,
        );
        assert_eq!(
            i32::from_le_bytes([w.payload[4], w.payload[5], w.payload[6], w.payload[7]]),
            2000,
        );
        assert_eq!(u16::from_le_bytes([w.payload[8], w.payload[9]]), 7);
        assert_eq!(w.payload[10], 0x5A);

        let e = rec(2);
        assert_eq!(e.kind, LOG_EVT_SKILL_END);
        assert_eq!(u16::from_le_bytes([e.payload[0], e.payload[1]]), 0x0BAD);
        assert_eq!(e.payload[2], 0x33);
        logger_shutdown();
    }

    /// A full ring overwrites the oldest record and counts the loss. Losing
    /// the oldest is the right direction for a flight recorder — the newest
    /// events are the ones that explain a crash — but it must be counted,
    /// or an analyst reads a gapped log as a complete one.
    #[test]
    fn a_full_ring_drops_the_oldest_and_says_how_many() {
        let _g = start();
        logger_init().expect("mount succeeds");
        for i in 0..(LOG_RING_CAPACITY + 5) {
            log_skill_start(i as u16);
        }
        assert_eq!(logger_ring_len(), LOG_RING_CAPACITY, "the ring is bounded");
        assert_eq!(
            logger_analytics().events_dropped, 5,
            "every overwritten record must be counted",
        );
        // The survivors are the NEWEST, and they are still in order.
        logger_flush().unwrap();
        let bytes = fsmock::file_bytes(0);
        let body = &bytes[LOG_FILE_HEADER_BYTES..];
        assert_eq!(body.len() / LOG_RECORD_SIZE, LOG_RING_CAPACITY);
        let first = {
            let mut b = [0u8; LOG_RECORD_SIZE];
            b.copy_from_slice(&body[..LOG_RECORD_SIZE]);
            LogRecord::decode(&b)
        };
        assert_eq!(
            u16::from_le_bytes([first.payload[0], first.payload[1]]), 5,
            "records 0..4 were the ones overwritten",
        );
        logger_shutdown();
    }

    /// The ring empties in one flush even though a flush now writes in
    /// 16-record chunks. Without the loop a full ring would need 8 calls and
    /// the watermark tick would never catch up with a busy robot.
    #[test]
    fn one_flush_empties_a_full_ring_despite_chunking() {
        let _g = start();
        logger_init().expect("mount succeeds");
        for i in 0..LOG_RING_CAPACITY {
            log_skill_start(i as u16);
        }
        assert!(LOG_RING_CAPACITY > LOG_FLUSH_BATCH_MAX, "otherwise this proves nothing");
        assert_eq!(logger_flush().unwrap(), LOG_RING_CAPACITY);
        assert_eq!(logger_ring_len(), 0);
        logger_shutdown();
    }

    /// Files are named `/LOG/LOGNNNNN.BIN` — a decoder, and any `LogStorage`
    /// implementation that has to turn a serial into a real path, depends on
    /// this exact byte layout. Tested directly against `make_log_path`
    /// rather than through a mock's recorded path: a `LogStorage`
    /// implementation is free to lay out paths/volumes/directories however
    /// it needs to (see `tools/tcb_check.sh` — that used to be FAT32's `mkdir`
    /// plumbing, now the implementation's own business), so the mock has
    /// nothing meaningful to assert about directory creation any more. What
    /// stays load-bearing across every implementation is the naming scheme
    /// itself, and the fact that it is the single source both the recorder
    /// and a storage implementation must use.
    #[test]
    fn log_files_are_named_by_serial() {
        let mut p = [0u8; 17];
        make_log_path(42, &mut p);
        assert_eq!(&p[0..LOG_DIR_PATH.len()], LOG_DIR_PATH, "must live under /LOG");
        assert_eq!(p[LOG_DIR_PATH.len()], b'/');
        assert_eq!(&p[13..17], b".BIN");
        assert_eq!(&p[8..13], b"00042", "the serial field is 5 zero-padded decimal digits");

        // The wrap point (SAFETY_LOG_WRAPPED / LOG_SERIAL_WRAP) reuses
        // filenames on purpose — this is what makes that reuse concrete.
        let mut wrapped = [0u8; 17];
        make_log_path(LOG_SERIAL_WRAP + 42, &mut wrapped);
        assert_eq!(wrapped, p, "serial % LOG_SERIAL_WRAP must reuse the same filename");
    }

    /// **Wrap ordering.** `open_log_file`'s own comment says the wrap notice
    /// is "recorded BEFORE the truncate" -- `log_safety_violation` runs, and
    /// only then does `storage.open()` truncate the post-wrap file. Pinned
    /// by snapshotting `safety_violations` at the instant `open()` runs for
    /// that file: the counter must already be non-zero, not still waiting
    /// for a call that hasn't happened yet.
    ///
    /// Reaches the wrap path through a real rotation (the realistic case —
    /// `LOG_ACTIVE` is already true, unlike a cold `logger_init` at a
    /// pre-seeded high serial), using the same forced-torn-write trick as
    /// `a_device_that_stalls_mid_record_rotates_instead_of_corrupting_the_rest`
    /// to trigger it without writing 100,000 real files.
    #[test]
    fn the_wrap_notice_is_logged_before_the_truncating_open() {
        let _g = start();
        set_serial_for_test(LOG_SERIAL_WRAP - 1);
        logger_init().expect("mount succeeds"); // file 0, serial WRAP-1
        log_skill_start(1);

        // Write #0 was the header. Write #1 (this record) takes half, and
        // write #2 (the retry) then fails outright -- the same two-fault
        // combination `a_device_that_stalls_mid_record_rotates_instead_of_corrupting_the_rest`
        // uses, because a short write alone is just completed by the retry
        // (see that test) and never tears. This forces `logger_flush` to
        // rotate regardless of file size.
        fsmock::with(|r| {
            r.short_write_at = Some((1, 16));
            r.fail_write_at = Some(2);
        });
        assert!(logger_flush().is_err(), "the torn write must be reported");

        // Rotation opened file 1 for serial LOG_SERIAL_WRAP -- past the wrap
        // point, so `open_log_file` must have logged SAFETY_LOG_WRAPPED
        // before calling `storage.open()` for it.
        assert_eq!(fsmock::file_count(), 2, "the wrap must have opened a second file");
        let sv_at_open = fsmock::with(|r| r.files[1].safety_violations_at_open);
        assert!(
            sv_at_open >= 1,
            "storage.open() for the post-wrap file ran with safety_violations={sv_at_open}; \
             the wrap notice must be logged before the truncating open, not after",
        );

        // Ordering alone was the whole of this test, and ordering alone is
        // not the property that matters: the notice is about a file whose
        // history is being discarded, so it has to BE in that file. Scanned
        // raw rather than through `decode_file` because this path reaches
        // rotation by tearing a write, so file 0 deliberately does not end
        // on a record boundary.
        let old = fsmock::file_bytes(0);
        assert!(
            wrap_notice_offset(&old).is_some(),
            "the outgoing file must carry the notice describing its own end; \
             {} body bytes and no SAFETY_LOG_WRAPPED record in them",
            old.len() - LOG_FILE_HEADER_BYTES,
        );
        logger_shutdown();
    }

    /// Byte offset of the first `SAFETY_LOG_WRAPPED` record in a raw file, or
    /// `None`.
    ///
    /// Record layout (pinned by `a_record_is_the_documented_32_bytes`):
    /// `[ts u64 LE][kind u8][flags u8][pad u16][payload 20B]`, so `kind` is
    /// byte 8 and `payload[0]` — the violation code — is byte 12. Scans every
    /// byte offset instead of stepping 32 at a time because the file this is
    /// used on may have a torn record in it.
    fn wrap_notice_offset(bytes: &[u8]) -> Option<usize> {
        (LOG_FILE_HEADER_BYTES..bytes.len().saturating_sub(LOG_RECORD_SIZE - 1))
            .find(|&i| {
                bytes[i + 8] == LOG_EVT_SAFETY_VIOLATION
                    && bytes[i + 12] == SAFETY_LOG_WRAPPED
            })
    }

    /// **A deep ring at the instant of the tear.** The notice is pushed to
    /// the TAIL of the ring, and one `flush_one_batch` pass takes at most
    /// `LOG_FLUSH_BATCH_MAX` records from the HEAD. So carrying the notice
    /// out with a single pass only works while fewer than a batch is queued
    /// ahead of it — which is exactly what
    /// `the_wrap_notice_is_logged_before_the_truncating_open` sets up (one
    /// record), and exactly what a real fault does not.
    ///
    /// A torn write stops the drain WITHOUT consuming, so the ring still
    /// holds everything it held when the device faulted. Here that is
    /// `LOG_FLUSH_BATCH_MAX * 2 + 1` records ahead of the notice: one pass
    /// reaches none of it, and the notice rides into the new file again.
    #[test]
    fn the_wrap_notice_still_lands_when_a_full_batch_is_queued_ahead_of_it() {
        let _g = start();
        set_serial_for_test(LOG_SERIAL_WRAP - 1);
        logger_init().expect("mount succeeds"); // file 0, serial WRAP-1

        let queued = LOG_FLUSH_BATCH_MAX * 2 + 1;
        assert!(
            queued + 1 < LOG_RING_CAPACITY,
            "the notice must still fit on the ring, or this measures a drop instead",
        );
        for i in 0..queued { log_skill_start(i as u16); }

        // Same two-fault trick as the ordering test: write #0 was the
        // header, write #1 takes half a record, write #2 fails outright.
        // The drain stops having consumed NOTHING, so all `queued` records
        // are still ahead of the notice on the ring.
        fsmock::with(|r| {
            r.short_write_at = Some((1, 16));
            r.fail_write_at = Some(2);
        });
        assert!(logger_flush().is_err(), "the torn write must be reported");
        assert_eq!(fsmock::file_count(), 2, "the tear must have rotated");

        assert!(
            wrap_notice_offset(&fsmock::file_bytes(0)).is_some(),
            "the notice must reach the outgoing file even with {queued} records \
             queued ahead of it — one batch pass is not a drain",
        );
        assert!(
            wrap_notice_offset(&fsmock::file_bytes(1)).is_none(),
            "and it must not also be sitting in the file that opened after it",
        );
        logger_shutdown();
    }

    /// **Where the notice lands.** The serial wraps, `make_log_path` reuses
    /// the filename, and the open truncates a file that still held history.
    /// The notice exists so whoever reads the logs afterwards can tell "the
    /// machine had just started" from "the beginning was overwritten" — which
    /// only works if the notice is in the file whose ending it describes.
    ///
    /// It was not. `open_log_file` emitted it, and `open_log_file` runs after
    /// `logger_flush` has already set `LOG_FILE` to `None`: the record stayed
    /// queued on the ring and reached disk inside the NEXT file, the one that
    /// had just discarded the history it was reporting. The function's own
    /// comment said so and called the fix "real work, not attempted here".
    ///
    /// Rotation here is reached by SIZE, not by a fault, so the outgoing file
    /// is a whole number of records and a decoder can read it — the torn path
    /// is covered by `the_wrap_notice_is_logged_before_the_truncating_open`.
    #[test]
    fn the_wrap_notice_lands_in_the_file_whose_ending_it_describes() {
        let _g = start();
        set_serial_for_test(LOG_SERIAL_WRAP - 1);
        logger_init().expect("mount succeeds"); // file 0, serial WRAP-1

        // Fill until `bytes_written` crosses LOG_FILE_ROTATE_BYTES. Bounded
        // by construction, and the loop stops the moment the second file
        // appears so nothing is written into it by accident.
        let rounds = LOG_FILE_ROTATE_BYTES as usize / LOG_RECORD_SIZE / LOG_RING_CAPACITY + 2;
        for _ in 0..rounds {
            if fsmock::file_count() > 1 { break; }
            for i in 0..LOG_RING_CAPACITY { log_skill_start(i as u16); }
            logger_flush().expect("no faults are injected here");
        }
        assert_eq!(
            fsmock::file_count(), 2,
            "the size-driven rotation never happened, so this test proves nothing",
        );

        let old = super::flight_recorder::decode_file(0);
        let last = old.last().expect("the outgoing file must have records");
        assert_eq!(
            (last.kind, last.payload[0]),
            (LOG_EVT_SAFETY_VIOLATION, SAFETY_LOG_WRAPPED),
            "the LAST record of the file being retired must be the wrap notice; \
             found kind={:#04x} code={:#04x}", last.kind, last.payload[0],
        );
        let named = u32::from_le_bytes(last.payload[4..8].try_into().unwrap());
        assert_eq!(
            named, LOG_SERIAL_WRAP,
            "the notice must name the serial whose filename is being reused",
        );

        // And exactly once. Under the old code the record was still sitting
        // on the ring at this point and the next flush put it in the NEW
        // file; give that flush something to carry and check it did not.
        log_skill_start(7);
        logger_flush().expect("the new file is healthy");
        let new = super::flight_recorder::decode_file(1);
        assert!(
            !new.is_empty(), "the follow-up flush must have written something",
        );
        assert!(
            new.iter().all(|r| !(r.kind == LOG_EVT_SAFETY_VIOLATION
                                 && r.payload[0] == SAFETY_LOG_WRAPPED)),
            "the notice must not also appear in the file that opened after it",
        );
        logger_shutdown();
    }

    /// `logger_init` is documented idempotent, and a storage implementation
    /// that refuses to open must leave the logger inactive rather than
    /// half-started — event calls become no-ops instead of pushing into a
    /// ring that will never be flushed.
    #[test]
    fn a_failed_open_leaves_the_logger_inactive() {
        let _g = start();
        fsmock::with(|r| r.open_fails = true);
        assert!(logger_init().is_err());
        log_skill_start(1);
        assert_eq!(logger_ring_len(), 0, "an inactive logger must not accumulate records");
        assert_eq!(fsmock::file_count(), 0);

        fsmock::with(|r| r.open_fails = false);
        logger_init().expect("now it opens");
        log_skill_start(1);
        assert_eq!(logger_ring_len(), 1);
        // Second init is a no-op: no second file, no second serial.
        logger_init().expect("idempotent");
        assert_eq!(fsmock::file_count(), 1);
        logger_shutdown();
    }

    /// Analytics accounting: distance accumulates only on positive deltas,
    /// battery is reported in mAh from µAh, safety violations are counted,
    /// and a reset zeroes all of it.
    #[test]
    fn the_analytics_counters_add_up_and_reset() {
        let _g = start();
        logger_init().expect("mount succeeds");
        log_sensor_snapshot(3700, 100, 1500, 0);
        log_sensor_snapshot(3700, 100, 0, 0);      // no distance to add
        log_sensor_snapshot(3700, 100, 500, 0);
        logger_add_battery_uah(2_500_000);
        log_safety_violation(1, 2, 3);
        log_safety_violation(1, 2, 4);

        let a = logger_analytics();
        assert_eq!(a.total_distance_mm, 2000);
        assert_eq!(a.battery_mah_used, 2500, "µAh -> mAh is integer division");
        assert_eq!(a.safety_violations, 2);
        assert_eq!(a.events_dropped, 0);
        assert_eq!(a.flush_errors, 0);

        logger_analytics_reset();
        let a = logger_analytics();
        assert_eq!(a.total_distance_mm, 0);
        assert_eq!(a.battery_mah_used, 0);
        assert_eq!(a.safety_violations, 0);
        logger_shutdown();
    }

    /// `logger_shutdown` must get the tail of the mission onto the medium —
    /// it is the last chance before power goes away.
    #[test]
    fn shutdown_flushes_what_is_still_in_the_ring() {
        let _g = start();
        logger_init().expect("mount succeeds");
        for i in 0..3u16 { log_skill_start(i); }
        assert_eq!(fsmock::file_bytes(0).len(), LOG_FILE_HEADER_BYTES, "nothing written yet");
        logger_shutdown();
        assert_eq!(
            fsmock::file_bytes(0).len(),
            LOG_FILE_HEADER_BYTES + 3 * LOG_RECORD_SIZE,
            "the 3 pending records must reach the file",
        );
        assert!(fsmock::with(|r| r.files[0].closed), "and the file must be closed");
    }
}

// ---------------------------------------------------------------------------
// RFC-0037: what a semantic-level packet puts in the flight recorder.
// ---------------------------------------------------------------------------
//
// The two handlers that receive `PKT_SEMANTIC_LEVEL` — the network link and
// the UART bridge — live in `kernel/src/tasks/behavior.rs` and are not reachable from a
// host test. The decision they both make is, so it was pulled out into
// `logger::semantic_level_record` and both call it. These tests are the reason
// that extraction was worth doing: the policy has four cases and three of them
// are easy to get backwards in an `else if` chain nobody can execute.

#[cfg(test)]
mod semantic_level_records {
    use super::logger::{
        semantic_level_record, SAFETY_SEMANTIC_LEVEL, SAFETY_SEMANTIC_MALFORMED,
    };

    /// Owner decision, 2026-09-05: every level change is recorded, not only
    /// the transition into CONTAINED. The graded levels exist to answer *why
    /// the robot was moving slowly*, and recording only the stop would leave
    /// exactly that question unanswered.
    #[test]
    fn every_level_change_is_recorded_not_just_containment() {
        for (prev, new) in [(0u8, 1u8), (1, 2), (2, 3), (3, 0), (0, 3), (2, 1)] {
            let r = semantic_level_record(false, new, prev);
            assert_eq!(
                r, Some((SAFETY_SEMANTIC_LEVEL, new, prev as u32)),
                "the transition {prev} -> {new} went unrecorded"
            );
        }
    }

    /// The record carries where it came FROM as well as where it went. A
    /// reader of the flight recorder needs the transition: "dropped to SLOW"
    /// and "climbed to SLOW" are different events with the same destination.
    #[test]
    fn the_record_carries_the_level_it_replaced() {
        let (_, action, detail) = semantic_level_record(false, 1, 3).unwrap();
        assert_eq!(action, 1, "action must carry the new level");
        assert_eq!(detail, 3, "detail must carry the level it replaced");
    }

    /// The level is sticky by design and the brain may resend a standing level
    /// at any cadence it likes. Recording repeats would fill the medium with
    /// the fact that nothing happened — and the medium is a 100k-file circular
    /// log, so filling it with non-events discards real history.
    #[test]
    fn restating_the_level_already_in_force_records_nothing() {
        for level in 0..=3u8 {
            assert_eq!(
                semantic_level_record(false, level, level), None,
                "a no-op repeat at level {level} was recorded"
            );
        }
    }

    /// **A truncated packet is recorded even when it changes nothing.**
    ///
    /// This is the case an `else if` chain gets wrong, and it is the one that
    /// matters most. The kernel's fail-closed path turns a missing payload
    /// into CONTAINED; if the robot is already CONTAINED, nothing changes —
    /// but the event being recorded is not the transition. It is that the
    /// kernel could not tell what was asked and stopped, which is a link
    /// fault or a hostile sender, not a decision. Ordering the "did it
    /// change" check first would make the fail-closed path invisible in the
    /// record at exactly the moment it fired.
    #[test]
    fn a_malformed_packet_is_recorded_even_when_the_level_does_not_change() {
        assert_eq!(
            semantic_level_record(true, 3, 3),
            Some((SAFETY_SEMANTIC_MALFORMED, 3, 3)),
            "a truncated packet arriving at an already-contained robot left no trace"
        );
    }

    /// And a malformed packet is never filed as an ordinary level change, at
    /// any transition — the two codes exist to be told apart by whoever reads
    /// the log after an incident.
    #[test]
    fn a_malformed_packet_is_never_filed_as_an_ordinary_change() {
        for prev in 0..=3u8 {
            let (code, _, _) = semantic_level_record(true, 3, prev).unwrap();
            assert_eq!(
                code, SAFETY_SEMANTIC_MALFORMED,
                "a truncated packet over level {prev} was filed as a normal change"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Golden wire vectors, shared with `tools/fake_brain.py`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod wire_golden {
    use super::brain_protocol::{build_packet, PKT_SEMANTIC_LEVEL, PKT_DEGRADE};

    /// The exact bytes `tools/fake_brain.py` puts on the wire.
    ///
    /// That script transcribes CRC-8/MAXIM into Python so a QEMU scenario can
    /// send a frame this kernel must refuse. A transcription that drifted would
    /// not announce itself: every frame would fail the CRC check inside
    /// `parse_packet` and be dropped BEFORE reaching the dispatch, so the
    /// scenario's log would look exactly like a kernel that ignored the frames
    /// — the failure mode the scenario exists to detect, produced by the test
    /// harness instead of by the kernel.
    ///
    /// Pinning the bytes here makes that drift a red test in either direction:
    /// change the framing in Rust and this fails, change it in Python and its
    /// `--selftest` fails against the same vectors.
    #[test]
    fn the_frames_the_fake_brain_sends_are_these_bytes() {
        let mut out = [0u8; 16];

        // Empty payload: the frame the fail-closed branch of the semantic-level
        // handler exists for. Six bytes, length zero, CRC over the header.
        let n = build_packet(PKT_SEMANTIC_LEVEL, &[], &mut out);
        assert_eq!(&out[..n], &[0x42, 0x52, 0x8B, 0x00, 0x00, 0xC4],
            "the empty SEMANTIC_LEVEL frame changed; tools/fake_brain.py sends \
             the old bytes and its frames will now be dropped at the CRC check \
             rather than reaching the dispatch");

        // One byte, out of range: exercises a non-zero length field too.
        let n = build_packet(PKT_SEMANTIC_LEVEL, &[200], &mut out);
        assert_eq!(&out[..n], &[0x42, 0x52, 0x8B, 0x01, 0x00, 200, 0x3B],
            "the out-of-range SEMANTIC_LEVEL frame changed");

        // The DEGRADE frame whose absent reason byte used to CLEAR containment.
        let n = build_packet(PKT_DEGRADE, &[], &mut out);
        assert_eq!(&out[..n], &[0x42, 0x52, 0x8A, 0x00, 0x00, 0x82],
            "the empty DEGRADE frame changed");
    }
}

// ── What a remote ActuatorCmd means ─────────────────────────────────────
//
// The kernel handles these frames in two places — the TCP brain link and the
// UART bridge — and they were COPIES. When the emergency path was found to
// last exactly one behaviour tick, the fix went into the TCP copy and the UART
// copy kept the bug. `remote_actuation_from` is that decision extracted so
// there is one of it.
//
// This module is the only coverage the UART side can have. Its transport is
// `cfg(feature = "vf2")` and reads a UART that does not exist on QEMU's virt
// machine (`bridge_is_ready()` is a literal `false` in every QEMU build), so
// no scenario can drive it. The decision is testable; the wire waits for the
// board, and this comment says so rather than letting a green suite imply
// otherwise.
// ── A packet handler must not busy-wait ───────────────────────────────────
//
// `payload_cam_trigger` held the shutter line high with
// `while get_time() - start < 500_000 {}` — 50 ms — and its caller is the
// `PKT_PAYLOAD` arm of `behavior_task`'s dispatch loop. An 11-byte frame, and
// the loop consumes every frame coalesced into one 256-byte read: 23 of them
// bought 1.15 s of stall on the hart that runs L0, per read. The pulse is a
// deadline now, retired by `payload_tick` on a later pass of the same loop.
#[cfg(test)]
mod cam_trigger_does_not_spin {
    use super::payload::{
        cam_pulse_is_done, payload_cam_trigger, payload_cam_trigger_active,
        payload_tick, CAM_TRIGGER_PULSE_TICKS, PAYLOAD_GPIO_CAM_TRIGGER,
    };
    use azos_drv_gpio::gpio::gpio_read;

    /// **The property that removes the peer's leverage**, and it needs no
    /// clock: a second trigger arriving in the same dispatch loop — which is
    /// what a coalesced flood IS — is refused rather than costing another
    /// pulse. The first one raised the line and returned immediately.
    #[test]
    fn a_second_trigger_inside_the_pulse_is_refused() {
        assert!(payload_cam_trigger(), "the first trigger fires");
        assert_eq!(gpio_read(PAYLOAD_GPIO_CAM_TRIGGER), 1,
                   "and it really does raise the shutter line");
        for i in 0..23 {
            assert!(!payload_cam_trigger(),
                    "re-trigger #{} landed inside the in-flight pulse", i + 1);
        }
        assert!(payload_cam_trigger_active(), "the pulse is still in flight");
        assert_eq!(gpio_read(PAYLOAD_GPIO_CAM_TRIGGER), 1,
                   "and a refused re-trigger must not drop the line either");
        // `payload_tick` this soon must NOT retire it: the width is 50 ms and
        // no test takes that long between two statements.
        payload_tick();
        assert!(payload_cam_trigger_active(),
                "the pulse must last its full width, not until the next tick");
    }

    /// The width itself, as a pure function, so the deadline arithmetic is
    /// pinned without pinning the clock.
    #[test]
    fn the_pulse_lasts_its_full_width() {
        assert!(!cam_pulse_is_done(1_000, 1_000), "not at the instant it starts");
        assert!(!cam_pulse_is_done(1_000, 1_000 + CAM_TRIGGER_PULSE_TICKS - 1),
                "not one tick short of the width");
        assert!(cam_pulse_is_done(1_000, 1_000 + CAM_TRIGGER_PULSE_TICKS),
                "exactly at the width");
        assert!(cam_pulse_is_done(1_000, u64::MAX), "and after it");
    }
}

#[cfg(test)]
mod payload_refuses_while_latched {
    //! H22 (coordinator audit, 2026-09-26): `payload_exec` had no e-stop
    //! check — a 12 V spray pump kept running through a latched e-stop.
    use super::payload::{payload_exec, payload_spray_active};
    use super::brain_protocol::{PayloadCmd, PAYLOAD_TYPE_SPRAY, PAYLOAD_OFF};
    use super::safety::*;

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        super::envelope::serial()
    }

    fn reset() {
        estop_release(ReleaseAuthority::for_test());
    }

    fn spray_on() -> PayloadCmd {
        PayloadCmd { payload_type: PAYLOAD_TYPE_SPRAY, channel: 0, value: PAYLOAD_OFF + 1, duration_ms: 0 }
    }

    /// **RED before the fix** (reproduced by reverting `payload_exec`'s new
    /// `estop_is_active()` check): `payload_exec(spray_on())` returned
    /// `true` and the pump turned on while the latch held. See the agent
    /// report for the exact captured output.
    #[test]
    fn a_spray_command_is_refused_while_latched() {
        let _g = serial();
        reset();
        estop_activate();
        assert!(!payload_exec(spray_on()), "a payload command must be refused while latched");
        assert!(!payload_spray_active(), "the pump must not have been turned on");
    }

    /// The positive half: with no violation, the SAME command is admitted.
    #[test]
    fn a_spray_command_is_admitted_once_released() {
        let _g = serial();
        reset();
        assert!(payload_exec(spray_on()), "with the latch released, the command must be admitted");
        assert!(payload_spray_active(), "and must actually turn the pump on");
        // Leave the pump as this test found it able to leave it: off.
        assert!(super::payload::payload_spray(false));
    }

    /// The seam every e-stop source's `latch_and_stop` calls must physically
    /// stop an ALREADY-RUNNING pump, not just refuse the next command.
    /// `domains/robot/safety-core::actuation::latch_and_stop` itself is not pulled
    /// into this crate, so this exercises the pump-stop half it calls
    /// directly, alongside `estop_activate` standing in for the latch half.
    #[test]
    fn payload_emergency_stop_turns_an_already_running_pump_off() {
        let _g = serial();
        reset();
        assert!(payload_exec(spray_on()));
        assert!(payload_spray_active(), "precondition: the pump is running");
        estop_activate();
        super::payload::payload_emergency_stop();
        assert!(!payload_spray_active(), "the pump must stop immediately, not on the next command");
    }
}

// ── A refused e-stop clear must not be an unmetered durable write ──────────
//
// Found 2026-09-11, same audit. `PKT_MODE` with any id other than the reset
// one, while the e-stop is armed, is refused — and used to cost a synchronous
// flight-recorder flush and a console line EVERY TIME, for a frame that
// changes no state. Seven bytes on the wire, 36 of them per 256-byte read.
// The identical defect on the ring-3 path was already closed, with the
// argument written out in `ring3_estop`; this is its remote twin.
#[cfg(test)]
mod refused_estop_clears_are_metered {
    use super::estop::refusal_is_worth_recording;

    /// The pure half. The stateful half is one `fetch_add` over this in
    /// `safety::note_refused_estop_clear`, reset wherever the latch changes.
    #[test]
    fn the_first_and_then_powers_of_ten_are_recorded() {
        // `prior` is the count BEFORE this refusal, so `prior = 0` is the 1st.
        assert!(refusal_is_worth_recording(0), "the first refusal is information");
        for prior in 1..9u32 {
            assert!(!refusal_is_worth_recording(prior),
                    "refusal #{} is a copy of the first", prior + 1);
        }
        assert!(refusal_is_worth_recording(9), "the 10th says it kept happening");
        for prior in 10..99u32 {
            assert!(!refusal_is_worth_recording(prior), "#{}", prior + 1);
        }
        assert!(refusal_is_worth_recording(99));
        assert!(refusal_is_worth_recording(999));
        assert!(refusal_is_worth_recording(9_999));
        assert!(!refusal_is_worth_recording(u32::MAX), "no overflow, no panic");
    }

    /// **The property is the BOUND**, not which particular ordinals pass: a
    /// peer that keeps sending must not be able to make the recorder write
    /// more than a handful of times however long it keeps going. Asserted as a
    /// count over a run of 100 000 refusals, which is what a rate limiter
    /// would fail — one per second over a 45 s scenario is 45 records.
    #[test]
    fn a_flood_costs_a_bounded_number_of_records() {
        let n = (0..100_000u32).filter(|p| refusal_is_worth_recording(*p)).count();
        assert_eq!(n, 6,
                   "1st, 10th, 100th, 1000th, 10 000th, 100 000th — and nothing else");
    }
}

// ── A ring-3 re-latch after an operator clear is attributable ──────────────
//
// Audit unit 1. Only `MODE_ID_ESTOP_RESET` clears the latch, and `ring3_estop`
// early-returns only while it holds — so a ring-3 program can latch again the
// instant an operator clears it. That must stay a stop (a stop is never
// refused), but the record wrote action 4, shared with a refused clear, and
// `detail = 0`: it could not say which program did it, nor that it undid a
// clear. `ring3_estop` in `domains/robot/safety-core/src/actuation.rs` now writes
// what `safety::ring3_estop_record` returns.
#[cfg(test)]
mod ring3_relatch_is_attributed {
    use super::estop::relatched_within_window;
    use super::safety::*;

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        super::envelope::serial()
    }

    /// The pure half, at both edges of the window and on the sentinels.
    #[test]
    fn the_window_is_inclusive_and_starts_at_the_clear() {
        assert!(!relatched_within_window(0, 5, 10), "never cleared is never a re-latch");
        assert!(relatched_within_window(100, 100, 10), "the same tick is inside");
        assert!(relatched_within_window(100, 110, 10), "the last tick of the window is inside");
        assert!(!relatched_within_window(100, 111, 10), "one past the window is outside");
        assert!(!relatched_within_window(100, 99, 10), "a clear after the stop released it");
    }

    /// **The stateful half.** An operator clear stamps the latch, and a ring-3
    /// stop inside the window says so with the tid; one tick past it, only the
    /// tid. The action code is its own, not the refused clear's 4.
    #[test]
    fn a_clear_is_stamped_and_a_ring3_stop_inside_the_window_says_so() {
        let _g = serial();
        estop_activate();
        estop_release(ReleaseAuthority::for_test());
        let cleared = estop_cleared_at();
        assert_ne!(cleared, 0, "an operator clear must stamp the latch");

        let w = ESTOP_RELATCH_WINDOW_TICKS;
        assert_eq!(w, 100_000_000, "10 s at the suite's 10 MHz timebase");
        assert_eq!(ring3_estop_record(42, cleared, cleared + w), (6, 0x8000_0000 | 42),
                   "a stop at the end of the window is a re-latch, and names task 42");
        assert_eq!(ring3_estop_record(42, cleared, cleared + w + 1), (6, 42),
                   "past the window it is an ordinary ring-3 stop, still attributed");
        assert_eq!(ring3_estop_record(u32::MAX, cleared, cleared + w + 1), (6, 0x7FFF_FFFF),
                   "a tid cannot forge the re-latch bit");
    }

    /// **A clear is spent when the latch arms again** (owner decision
    /// 2026-09-16). The stamp says "an operator clear is in effect"; it used
    /// to survive any number of stops, so a ring-3 stop within 10 s of a clear
    /// that ANOTHER source had already answered was recorded as undoing it.
    #[test]
    fn arming_the_latch_again_spends_the_operator_clear() {
        let _g = serial();
        estop_activate();
        estop_release(ReleaseAuthority::for_test());
        let cleared = estop_cleared_at();
        assert_ne!(cleared, 0, "an operator clear must stamp the latch");

        estop_activate(); // another source stops the machine inside the window
        assert_eq!(estop_cleared_at(), 0,
                   "arming the latch must spend the clear it answered");
        assert_eq!(ring3_estop_record(42, estop_cleared_at(), cleared + 1), (6, 42),
                   "with the clear spent, a ring-3 stop is an ordinary stop");
        estop_release(ReleaseAuthority::for_test());
    }
}

// ── An e-stop must survive its own clearing ────────────────────────────────
//
// Found 2026-09-11 auditing the remote command path. `PKT_ESTOP` latched the
// e-stop and stopped the wheels, and left `last_action` holding whatever drive
// command preceded it. The latch makes that harmless WHILE IT HOLDS — and the
// moment it is cleared, L2 finds an action younger than its 2 s window and
// re-publishes it. `ACTUATOR(100,100)` → `PKT_ESTOP` → `MODE 0xFF` put the
// robot at full speed on the CLEAR, with nothing commanding it after the stop.
//
// The same defect was found and fixed once already, for `FLAG_EMERGENCY`, in
// `remote_actuation_from` — see `an_emergency_replaces_the_cached_action_not_
// just_the_wheels` below. This is its sibling, and the fix went into
// `estop_activate` rather than into the two packet handlers so that the ring-3
// syscall and the physical kill switch are covered by the same line.
#[cfg(test)]
mod estop_replaces_the_standing_action {
    use super::layers::layer_remote_vla;
    use super::remote::{last_action, set_last_action};
    use super::safety::{estop_activate, estop_release, ReleaseAuthority};
    use super::types::{SensorState, VlaAction, CMD_MOTOR, CMD_STOP};

    fn driving_at_full_speed(at: u64) -> VlaAction {
        let mut a = VlaAction::new();
        a.cmd = CMD_MOTOR;
        a.actions[0] = 1000; // milli-units: L2 divides by 10 -> 100%
        a.actions[1] = 1000;
        a.received_at = at;
        a.valid = true;
        a
    }

    /// The assertion is what L2 EMITS, not what the latch says.
    ///
    /// Asserting `estop_is_active()` would pass on the broken code: the latch
    /// was never the missing half. And the state is stamped at the action's own
    /// `received_at`, so the test does not depend on a clock — the question is
    /// what the layer does with the action the e-stop installed, at the instant
    /// it installed it.
    #[test]
    fn clearing_an_estop_does_not_resume_the_command_that_preceded_it() {
        // Was unsynchronized against every other module's `estop_activate`/
        // `estop_release` on the same process-wide `ESTOP_ACTIVE` static —
        // found by `estop_release_authority.rs`'s tests intermittently seeing
        // the latch cleared by this test racing them. `envelope::serial()` is
        // the SAME lock `geofence`/`mode_reset`/`ring3_relatch_is_attributed`
        // already share for exactly this state.
        let _g = super::envelope::serial();
        // The robot domain's on-latch work, registered as
        // `azos_safety_core::actuation::install` registers it at boot
        // (wave 11: the latch moved to `azos_actuation`, which runs it).
        super::estop::register_on_latch_hook(super::safety::on_estop_latched);
        set_last_action(driving_at_full_speed(1_000));

        estop_activate();
        let cached = last_action();
        assert_eq!(cached.cmd, CMD_STOP,
                   "the standing action must BE the stop, not merely be overridden by it");
        assert_eq!(cached.actions[0], 0, "no residue of the command it replaced");
        assert_eq!(cached.actions[1], 0);

        // Now the operator clears it. Nothing else is sent.
        estop_release(ReleaseAuthority::for_test());
        let mut state = SensorState::new();
        state.remote_action = cached;
        state.timestamp = cached.received_at;

        let out = layer_remote_vla(&state);
        assert!(out.cmd.valid, "CMD_STOP is a command, so L2 must not abstain");
        assert_eq!((out.cmd.speed_l, out.cmd.speed_r), (0, 0),
                   "the clear must not hand the wheels back the pre-stop command");
    }
}

// ── The e-stop latch survives a reset ──────────────────────────────────────
//
// Owner decision, 2026-09-13: boot reads the last `SAFETY_ESTOP` in the durable
// record and starts latched if the previous session ended latched, or if a log
// file exists and cannot be read. Every boot opens serial 0 with TRUNCATE, so
// the kernel runs this before `logger_init`; these tests hand the decision every
// shape of disk it has to read correctly.
#[cfg(test)]
mod estop_latch_survives_a_reset {
    use super::logger::*;

    fn record(kind: u8, code: u8, action: u8) -> [u8; LOG_RECORD_SIZE] {
        let mut payload = [0u8; LOG_PAYLOAD_BYTES];
        payload[0] = code;
        payload[1] = action;
        let mut out = [0u8; LOG_RECORD_SIZE];
        LogRecord { ts: 1, kind, flags: 0, payload }.encode(&mut out);
        out
    }

    fn estop(action: u8) -> [u8; LOG_RECORD_SIZE] {
        record(LOG_EVT_SAFETY_VIOLATION, SAFETY_ESTOP, action)
    }

    /// A file as the recorder writes it: the 16-byte header, then records.
    fn file(records: &[[u8; LOG_RECORD_SIZE]]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(LOG_FILE_MAGIC);
        v.extend_from_slice(&LOG_FILE_VERSION.to_le_bytes());
        v.extend_from_slice(&[0u8; 10]);
        for r in records {
            v.extend_from_slice(r);
        }
        v
    }

    /// A file the recorder closed by rotation: `records`, then actuator records
    /// up to the rotation size.
    fn rotated(records: &[[u8; LOG_RECORD_SIZE]]) -> Vec<u8> {
        let mut v = file(records);
        let filler = record(LOG_EVT_ACTUATOR_CMD, 0, 0);
        while v.len() < LOG_FILE_ROTATE_BYTES as usize {
            v.extend_from_slice(&filler);
        }
        v
    }

    #[derive(Default)]
    struct Disk {
        files: Vec<Option<Vec<u8>>>,
        size_fails_at: Option<u32>,
        read_fails: bool,
        open: Option<(usize, usize)>,
        /// Every serial `open` was called on, in order.
        opened: Vec<u32>,
    }

    impl Disk {
        fn of(files: Vec<Option<Vec<u8>>>) -> Self {
            Disk { files, ..Default::default() }
        }
    }

    impl LogReplaySource for Disk {
        fn size(&mut self, serial: u32) -> Result<Option<u32>, LogStorageError> {
            if self.size_fails_at == Some(serial) {
                return Err(LogStorageError::Io);
            }
            Ok(self.files.get(serial as usize).and_then(|f| f.as_ref()).map(|f| f.len() as u32))
        }

        fn open(&mut self, serial: u32) -> Result<(), LogStorageError> {
            self.opened.push(serial);
            match self.files.get(serial as usize) {
                Some(Some(_)) => {
                    self.open = Some((serial as usize, 0));
                    Ok(())
                }
                _ => Err(LogStorageError::Unavailable),
            }
        }

        fn read(&mut self, buf: &mut [u8]) -> Result<usize, LogStorageError> {
            if self.read_fails {
                return Err(LogStorageError::Io);
            }
            let (idx, pos) = self.open.ok_or(LogStorageError::Unavailable)?;
            let bytes = self.files[idx].as_ref().unwrap();
            // Short on purpose: the seam promises `Ok(0)` only at end of file,
            // not full reads, and a reader that assumed them would misframe.
            let n = buf.len().min(bytes.len() - pos).min(100);
            buf[..n].copy_from_slice(&bytes[pos..pos + n]);
            self.open = Some((idx, pos + n));
            Ok(n)
        }

        fn close(&mut self) {
            self.open = None;
        }
    }

    fn boot(files: Vec<Option<Vec<u8>>>) -> BootLatch {
        replay_boot_latch(&mut Disk::of(files))
    }

    #[test]
    fn a_blank_medium_boots_released() {
        let b = boot(vec![]);
        assert_eq!(b, BootLatch::NoRecord);
        assert!(!b.latches());
    }

    #[test]
    fn a_session_that_ended_latched_boots_latched() {
        for source in [0u8, 1, 2, 4] {
            let b = boot(vec![Some(file(&[estop(source)]))]);
            assert_eq!(b, BootLatch::Armed(source), "source {}", source);
            assert!(b.latches());
        }
    }

    #[test]
    fn the_last_record_decides_not_the_first() {
        assert_eq!(boot(vec![Some(file(&[estop(2), estop(3)]))]), BootLatch::Released,
                   "stopped, then cleared by the operator");
        assert_eq!(boot(vec![Some(file(&[estop(3), estop(1)]))]), BootLatch::Armed(1),
                   "cleared, then stopped again");
    }

    /// Action 4 is a REFUSED clear, and in records written before the ring-3
    /// stop had its own code, the ring-3 stop too. Both are written only while
    /// the latch holds, so both mean latched.
    #[test]
    fn a_refused_clear_leaves_the_latch_armed() {
        assert_eq!(boot(vec![Some(file(&[estop(0), estop(4)]))]), BootLatch::Armed(4));
    }

    /// The ring-3 stop's own code must latch like every other stop — above
    /// all the one that re-latches straight after an operator clear.
    #[test]
    fn a_ring3_stop_after_a_clear_restores_latched() {
        let ring3 = super::safety::ESTOP_ACTION_RING3;
        assert_eq!(estop_action_latches(ring3), Some(true));
        assert_eq!(boot(vec![Some(file(&[estop(3), estop(ring3)]))]), BootLatch::Armed(ring3));
    }

    /// Wave 15: a dead motor commander's SAFE STOP (action 14) is recorded and
    /// never latches, so the next boot reads the record before it.
    #[test]
    fn a_commander_lost_record_neither_latches_nor_releases() {
        let lost = super::safety::ESTOP_ACTION_COMMANDER_LOST;
        assert_eq!(estop_action_latches(lost), None);
        assert_eq!(boot(vec![Some(file(&[estop(lost)]))]), BootLatch::Released);
        assert_eq!(boot(vec![Some(file(&[estop(0), estop(lost)]))]), BootLatch::Armed(0));
        assert_eq!(super::safety::commander_lost_detail(0x1234, 0b10), 0x0200_1234);
    }

    /// The self-check's synthetic record is neither a stop nor a clear, so it
    /// must not change what the record before it said.
    #[test]
    fn the_self_check_record_is_neither_a_stop_nor_a_clear() {
        assert_eq!(boot(vec![Some(file(&[estop(0), estop(7)]))]), BootLatch::Armed(0));
        assert_eq!(boot(vec![Some(file(&[estop(3), estop(7)]))]), BootLatch::Released);
        assert_eq!(boot(vec![Some(file(&[estop(7)]))]), BootLatch::Released);
    }

    /// A restore writes action 5. A second reset before anyone clears it must
    /// read that as latched too, or the latch survives exactly one power cycle.
    #[test]
    fn the_restore_record_survives_a_second_reset() {
        assert_eq!(estop_action_latches(ESTOP_ACTION_RESTORED), Some(true));
        assert_eq!(boot(vec![Some(file(&[estop(ESTOP_ACTION_RESTORED)]))]),
                   BootLatch::Armed(ESTOP_ACTION_RESTORED));
    }

    /// Only `SAFETY_ESTOP` records count. Other records carry a 2 and a 3 in the
    /// same two bytes — a degrade to level 3, a mode change from 2 to 3.
    #[test]
    fn only_estop_records_are_read() {
        let degrade_to_3 = record(LOG_EVT_SAFETY_VIOLATION, SAFETY_DEGRADE, 3);
        let mode_2_to_3 = record(LOG_EVT_MODE_CHANGE, SAFETY_ESTOP, 3);
        assert_eq!(boot(vec![Some(file(&[estop(0), degrade_to_3, mode_2_to_3]))]),
                   BootLatch::Armed(0));
    }

    #[test]
    fn a_recorder_that_cannot_be_read_boots_latched() {
        let mut bad_magic = file(&[estop(3)]);
        bad_magic[0] = b'X';
        assert_eq!(boot(vec![Some(bad_magic)]), BootLatch::Unreadable);

        let mut d = Disk::of(vec![Some(file(&[estop(3)]))]);
        d.read_fails = true;
        assert_eq!(replay_boot_latch(&mut d), BootLatch::Unreadable);

        let mut d = Disk::of(vec![Some(file(&[estop(3)]))]);
        d.size_fails_at = Some(0);
        assert_eq!(replay_boot_latch(&mut d), BootLatch::Unreadable);

        assert!(BootLatch::Unreadable.latches());
    }

    /// Owner decision, 2026-09-26 (U08-3): a crash between `open` and the
    /// header write leaves an empty file at the tail serial. Under the
    /// contiguous-serial scheme (`logger_seed_next_serial`) this is no
    /// longer evidence that a record was destroyed — nothing before this
    /// boot's aborted attempt was ever truncated — so it must not fail
    /// safe on its own. The walk falls back to the file below the empty
    /// one, and that file's own record decides.
    ///
    /// Before this decision, every session started at serial 0 and this
    /// exact byte pattern (`Vec::new()` at the tail) meant "THIS session's
    /// own record was erased mid-open", which had to fail `Unreadable`.
    #[test]
    fn a_crash_before_the_tail_files_header_falls_back_to_the_file_below_it() {
        assert_eq!(boot(vec![Some(file(&[estop(2)])), Some(Vec::new())]),
                   BootLatch::Armed(2));
    }

    /// Past the first read: the scan pulls sixteen records at a time through a
    /// seam that may return short, so a stop hundreds of records in must still
    /// be seen, and a clear after it must still win.
    #[test]
    fn a_stop_deep_in_a_long_file_is_found() {
        let filler = record(LOG_EVT_ACTUATOR_CMD, 0, 0);
        let mut recs = vec![filler; 300];
        recs.push(estop(1));
        assert_eq!(boot(vec![Some(file(&recs))]), BootLatch::Armed(1));
        recs.extend(std::iter::repeat(filler).take(37));
        recs.push(estop(3));
        assert_eq!(boot(vec![Some(file(&recs))]), BootLatch::Released);
    }

    #[test]
    fn a_torn_last_record_does_not_hide_the_one_before_it() {
        let mut f = file(&[estop(2)]);
        f.extend_from_slice(&estop(3)[..10]);
        assert_eq!(boot(vec![Some(f)]), BootLatch::Armed(2));
    }

    /// The stop was recorded, then the session rotated and wrote nothing else
    /// about it: the newest file holds no e-stop, the one before it does.
    #[test]
    fn a_stop_in_an_older_file_of_the_same_session_still_counts() {
        assert_eq!(boot(vec![Some(rotated(&[estop(2)])), Some(file(&[]))]),
                   BootLatch::Armed(2));
    }

    /// Owner decision, 2026-09-26 (U08-3): boot numbering is now contiguous
    /// across reboots, never reset to 0 (`logger_seed_next_serial`), so
    /// there is no such thing as a "stale file an older, longer session
    /// left above the tail" any more — every file up to the tail belongs to
    /// THIS lineage's own history, in order, and the newest one that
    /// decides still wins.
    ///
    /// Before this decision the premise here was the opposite: every
    /// session started at 0, so a file above where THIS session's own
    /// rotation reached had to be left by an earlier, longer-running
    /// session and was never opened at all.
    #[test]
    fn boot_numbering_is_contiguous_across_reboots_not_reset_to_zero() {
        let mut d = Disk::of(vec![
            Some(file(&[estop(0), estop(3)])), // an earlier boot: stopped, cleared
            Some(file(&[estop(2)])),           // the next boot: stopped again
        ]);
        assert_eq!(replay_boot_latch(&mut d), BootLatch::Armed(2));
        // The newest file alone already decides the LATCH, but `replay_boot`
        // (which `replay_boot_latch` wraps) also looks for a release-nonce
        // floor, and neither file has one, so the walk continues down to
        // serial 0 before giving up on that second answer — see
        // `replay_boot`'s own doc for why this cost is accepted.
        assert_eq!(d.opened, vec![1, 0]);
    }

    /// The newest file holding a stop or a clear decides the LATCH, so that
    /// answer stops there — but `replay_boot` (which `replay_boot_latch`
    /// wraps) also walks for a release-nonce floor and none of these three
    /// files has one, so the walk continues to serial 0 before giving up on
    /// that second answer. See `replay_boot`'s own doc for why this cost is
    /// accepted rather than stopping the whole walk at the latch decision.
    #[test]
    fn the_scan_stops_at_the_newest_file_that_decides() {
        let mut d = Disk::of(vec![
            Some(rotated(&[estop(3)])),
            Some(rotated(&[estop(0)])),
            Some(file(&[])),
        ]);
        assert_eq!(replay_boot_latch(&mut d), BootLatch::Armed(0));
        assert_eq!(d.opened, vec![2, 1, 0]);
    }
}

#[cfg(test)]
mod logger_serial_survives_a_reboot {
    //! U08-3, owner decision 2026-09-26: **the flight recorder must not
    //! erase the previous session's records on every boot.** Before this
    //! decision, `logger_init` always opened serial 0 with TRUNCATE
    //! (`open_flags::TRUNCATE` in `kernel/src/boot/robot.rs`'s `KernelLogStorage`)
    //! — this test proves boot 2's records land in a DIFFERENT file from
    //! boot 1's, and that boot 1's file is byte-for-byte untouched by boot 2.
    //!
    //! Uses `log_storage_mock` directly (not `flight_recorder::begin`,
    //! which resets the serial to 0 on every call — exactly the behaviour
    //! under test) across two explicit `logger_init`/`logger_shutdown`
    //! cycles standing in for two boots, with `replay_boot` — the same
    //! function `boot_latch::apply` calls in the real kernel, over the
    //! REAL `LogReplaySource` trait — deciding boot 2's starting serial in
    //! between, exactly as a real reboot would.
    use super::logger::*;
    use super::log_storage_mock as fsmock;

    /// Reads back through `fsmock`'s recorded files by OPEN-CALL INDEX,
    /// which this test's own two `logger_init` calls make identical to
    /// serial number (boot 1 opens serial 0 first; nothing else opens
    /// anything in this test).
    struct MockReplay;
    impl LogReplaySource for MockReplay {
        fn size(&mut self, serial: u32) -> Result<Option<u32>, LogStorageError> {
            if (serial as usize) < fsmock::file_count() {
                Ok(Some(fsmock::file_bytes(serial as usize).len() as u32))
            } else {
                Ok(None)
            }
        }
        fn open(&mut self, _serial: u32) -> Result<(), LogStorageError> { Ok(()) }
        fn read(&mut self, _buf: &mut [u8]) -> Result<usize, LogStorageError> {
            // Not exercised: this test only needs `replay_boot`'s
            // `next_serial` answer (from `replay_tail_serial`, which uses
            // `size` alone), not the latch decision, which is what would
            // call `open`/`read`.
            Ok(0)
        }
        fn close(&mut self) {}
    }

    #[test]
    fn boot_2_does_not_erase_boot_1s_actuator_record() {
        let _g = super::flight_recorder::SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        // Defensive: a preceding test under this same lock (any of them —
        // it is process-wide) may have left `LOG_ACTIVE` true if it forgot
        // its own `logger_shutdown()`. `logger_init()` below is a no-op on
        // an already-active logger, which would silently reuse whatever
        // file THAT test had open instead of opening "boot 1" fresh.
        // Idempotent: a no-op when the logger is already inactive.
        logger_shutdown();
        fsmock::reset();
        set_serial_for_test(0);
        logger_set_storage(&fsmock::STORAGE);

        // ---- boot 1 ----
        logger_seed_next_serial(0); // nothing to resume: a blank medium
        logger_init().expect("boot 1 logger_init");
        log_actuator_cmd(0, 1 /* Backward */, 50, 0, 0);
        logger_flush().expect("boot 1 flush");
        logger_shutdown();
        let boot1_bytes = fsmock::file_bytes(0);
        assert!(
            boot1_bytes.len() >= LOG_FILE_HEADER_BYTES + LOG_RECORD_SIZE,
            "boot 1 must have written its record before boot 2 starts",
        );

        // ---- boot 2: seed from a real scan, exactly like `boot_latch::apply` ----
        let next_serial = replay_tail_serial(|s| MockReplay.size(s))
            .expect("scan must not fail on a medium with one clean file")
            .map_or(0, |tail| tail + 1);
        assert_eq!(next_serial, 1, "boot 2 must resume ONE PAST boot 1's serial, not reuse it");
        logger_seed_next_serial(next_serial);
        logger_init().expect("boot 2 logger_init");
        log_actuator_cmd(0, 0 /* Forward */, 0, 0, 0);
        logger_flush().expect("boot 2 flush");

        // The property: boot 1's file is a DIFFERENT file, and it still
        // holds exactly what boot 1 wrote to it — nothing opened it again.
        assert_eq!(fsmock::file_count(), 2, "boot 2 must open a NEW file, not reopen serial 0");
        assert_eq!(
            fsmock::file_bytes(0), boot1_bytes,
            "boot 1's file must be byte-for-byte unchanged by boot 2 — \
             under the old scheme this would be empty (TRUNCATEd) or hold boot 2's record instead",
        );
        assert_eq!(fsmock::opened_serials(), vec![0, 1], "boot 2 opened serial 1, never reusing 0");

        logger_shutdown();
    }

    // `log_storage_mock` (used above, and by every OTHER logger test in this
    // file) is deliberately NOT serial-aware — unit 14's own finding calls
    // this out, and this test's own first run proved it empirically:
    // `MockStorage::open` pushes a fresh `MockFile` per CALL, indexed by
    // call order, not by the `serial` argument. So it cannot represent a
    // real re-`open` of the SAME serial truncating the SAME file — which is
    // exactly the defect this second test needs to reproduce. This mock is
    // serial-KEYED for that one reason: a real `open(serial)` with
    // `CREATE | TRUNCATE` always starts that serial's bytes over, whether
    // or not it already held something.
    struct SerialDisk { files: std::collections::HashMap<u32, Vec<u8>> }
    static SDISK: std::sync::Mutex<Option<SerialDisk>> = std::sync::Mutex::new(None);
    struct SerialStorage;
    static SSTORAGE: SerialStorage = SerialStorage;
    impl LogStorage for SerialStorage {
        fn open(&self, serial: u32) -> Result<LogHandle, LogStorageError> {
            let mut g = SDISK.lock().unwrap();
            let d = g.as_mut().expect("call reset_sdisk() first");
            d.files.insert(serial, Vec::new()); // CREATE | TRUNCATE, faithfully.
            Ok(LogHandle(serial))
        }
        fn write(&self, h: LogHandle, buf: &[u8]) -> Result<usize, LogStorageError> {
            let mut g = SDISK.lock().unwrap();
            g.as_mut().unwrap().files.get_mut(&h.0)
                .ok_or(LogStorageError::Unavailable)?.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn fsync(&self, _h: LogHandle) -> Result<(), LogStorageError> { Ok(()) }
        fn close(&self, _h: LogHandle) -> Result<(), LogStorageError> { Ok(()) }
    }
    fn reset_sdisk() { *SDISK.lock().unwrap() = Some(SerialDisk { files: std::collections::HashMap::new() }); }
    fn sdisk_bytes(serial: u32) -> Vec<u8> {
        SDISK.lock().unwrap().as_ref().unwrap().files.get(&serial).cloned().unwrap_or_default()
    }

    /// The whole point from the OTHER side: without the seed (this test's
    /// "RED" reproduction — the line commented below), boot 2 opens serial
    /// 0 AGAIN, and `SerialStorage::open` — mirroring the real
    /// `fat32_open(..., CREATE | TRUNCATE)` — starts that serial over,
    /// proving the erasure directly rather than asserting it symbolically.
    ///
    /// **Captured RED** (this exact test, with `logger_seed_next_serial`
    /// replaced by nothing — i.e. boot 2 relying on whatever `LOG_SERIAL`
    /// already was, which after `set_serial_for_test(0)` below is `0`,
    /// standing in for a fresh process): `boot 1's record is gone` fired —
    /// see the agent report for the exact `cargo test` output.
    #[test]
    fn without_the_seed_boot_2_would_truncate_boot_1_serial_0_again() {
        let _g = super::flight_recorder::SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        logger_shutdown(); // defensive — see the sibling test's comment.
        reset_sdisk();
        set_serial_for_test(0);
        logger_set_storage(&SSTORAGE);

        logger_seed_next_serial(0); // boot 1: nothing to resume.
        logger_init().expect("boot 1 logger_init");
        log_actuator_cmd(0, 1, 50, 0, 0);
        logger_flush().expect("boot 1 flush");
        logger_shutdown();
        assert!(sdisk_bytes(0).len() > LOG_FILE_HEADER_BYTES,
            "boot 1 must have written its record before boot 2 starts");

        // The pre-fix behaviour: a fresh process's `LOG_SERIAL` defaults to
        // `0` (simulated here by `set_serial_for_test(0)`, the same stand-in
        // `begin()` uses elsewhere in this file) and NOTHING seeds it from a
        // scan — so boot 2 opens serial 0 again.
        set_serial_for_test(0);
        logger_init().expect("boot 2 logger_init");
        assert!(
            sdisk_bytes(0).len() <= LOG_FILE_HEADER_BYTES,
            "boot 1's record is gone: boot 2's open() truncated the same file — \
             this IS the U08-3 defect, reproduced without the fix",
        );

        logger_shutdown();
        // Leave the registered storage as every other test expects it:
        // any subsequent logger test goes through `flight_recorder::begin`,
        // which re-registers `fsmock::STORAGE` itself, so nothing beyond
        // this line depends on cleaning up `LOG_STORAGE` by hand.
    }
}

#[cfg(test)]
mod remote_actuation {
    use super::brain_protocol::decode_actuator_cmd;
    use super::remote::{remote_actuation_from, REMOTE_PCT_TO_MILLI};
    use super::types::{VlaAction, CMD_MOTOR, CMD_NONE, CMD_STOP};

    const FLAG_EMERGENCY: u8 = 0x01;

    /// The wire payload, exactly as `brain_protocol.rs` documents it:
    /// `act_type, n_channels, flags, then i16 LE per channel`.
    fn payload(left: i16, right: i16, flags: u8) -> Vec<u8> {
        let mut p = vec![0u8, 2, flags];
        p.extend_from_slice(&left.to_le_bytes());
        p.extend_from_slice(&right.to_le_bytes());
        p
    }

    /// A previous action that is still valid and still driving — the state
    /// that made the one-tick bug possible in the first place.
    fn previously_driving(at: u64) -> VlaAction {
        let mut a = VlaAction::new();
        a.cmd = CMD_MOTOR;
        a.actions[0] = 600;
        a.actions[1] = 600;
        a.received_at = at;
        a.valid = true;
        a
    }

    /// **The half that was missing on the UART path for months.** Zeroing the
    /// wheels is not enough: unless the CACHED action is replaced, the next
    /// behaviour tick finds the previous command still unexpired and
    /// re-publishes it, and the emergency lasts ~100 ms.
    #[test]
    fn an_emergency_replaces_the_cached_action_not_just_the_wheels() {
        let cmd = decode_actuator_cmd(&payload(0, 0, FLAG_EMERGENCY)).unwrap();
        let plan = remote_actuation_from(&cmd, previously_driving(1_000), 5_000);

        assert!(plan.publish_stop, "an emergency publishes (0,0) directly");
        assert_eq!(plan.action.cmd, CMD_STOP,
                   "and the STANDING action becomes the stop, or it is undone next tick");
        assert_eq!(plan.action.actions[0], 0, "no residue of the command it replaced");
        assert_eq!(plan.action.actions[1], 0);
        assert_eq!(plan.action.received_at, 5_000,
                   "stamped NOW, so the age check does not expire it immediately");
        assert!(plan.action.valid);
    }

    /// **`CMD_STOP`, never `CMD_NONE`.** L2 matches on `cmd`, and `CMD_NONE`
    /// makes the layer ABSTAIN — which hands control to L1 and L3, both of
    /// which drive. Abstaining is not stopping, and the difference is one
    /// constant.
    #[test]
    fn the_stop_is_a_command_not_an_abstention() {
        let cmd = decode_actuator_cmd(&payload(0, 0, FLAG_EMERGENCY)).unwrap();
        let plan = remote_actuation_from(&cmd, previously_driving(1_000), 5_000);
        assert_ne!(plan.action.cmd, CMD_NONE,
                   "CMD_NONE makes L2 abstain and lets L1/L3 drive");
        assert_ne!(plan.action.cmd, CMD_MOTOR,
                   "a zeroed CMD_MOTOR would be re-scaled by the layer as a speed");
    }

    /// An ordinary command is NOT published directly: it goes into
    /// `remote_action` and through L0-L3, so L1 can still veto it. The
    /// emergency is the only thing that bypasses the layers, and that is the
    /// override-all semantic rather than an inconsistency.
    #[test]
    fn an_ordinary_command_is_routed_through_the_layers() {
        let cmd = decode_actuator_cmd(&payload(60, 60, 0)).unwrap();
        let plan = remote_actuation_from(&cmd, VlaAction::new(), 5_000);
        assert!(!plan.publish_stop, "only an emergency may bypass L0-L3");
        assert_eq!(plan.action.cmd, CMD_MOTOR);
    }

    /// **The ×10 that a real regression already cost.** `layer_remote_vla`
    /// divides `actions[]` by 10 to get the percent it commands, so a percent
    /// fed in unscaled ran the robot at a tenth of what the brain asked.
    /// Asserted as arithmetic on the constant, not as a magic 600, so the two
    /// cannot drift apart silently.
    #[test]
    fn percent_is_scaled_to_the_milli_units_the_layer_expects() {
        let cmd = decode_actuator_cmd(&payload(60, -40, 0)).unwrap();
        let plan = remote_actuation_from(&cmd, VlaAction::new(), 5_000);
        assert_eq!(plan.action.actions[0], (60 * REMOTE_PCT_TO_MILLI) as i16);
        assert_eq!(plan.action.actions[1], (-40 * REMOTE_PCT_TO_MILLI) as i16,
                   "reverse keeps its sign — a lost sign here drove FULL SPEED FORWARD once");
    }

    /// A drive command must not clear the rest of the action. `actions[]` has
    /// six slots and other producers use them; a remote wheel command owns two.
    #[test]
    fn a_drive_command_preserves_the_slots_it_does_not_own() {
        let mut prev = previously_driving(1_000);
        prev.actions[4] = 1234;
        let cmd = decode_actuator_cmd(&payload(10, 10, 0)).unwrap();
        let plan = remote_actuation_from(&cmd, prev, 5_000);
        assert_eq!(plan.action.actions[4], 1234,
                   "a wheel command owns actions[0..2] and nothing else");
    }
}

// ── RFC-0019: a sealed brain-link message is never dropped ────────────────
//
// Sealing consumes record counters and the brain accepts only the next one, so
// a sealed message the socket takes only part of must be finished, not dropped
// and not sealed again. Dropped, the next record reached the brain with a
// skipped counter and the gate's `link: rfc-0019 end to end` ended on
// `record counter out of sequence`. `brain_tx.rs` is the carry the kernel's
// transmit path uses for that; the socket and the clock are injected.

#[allow(dead_code)]
#[path = "../../../../domains/robot/behavior/src/brain_tx.rs"]
mod brain_tx;

// ── C1: the camera connection's sender policy ─────────────────────────────
//
// `camera_tx.rs` decides when the kernel's camera task dials the brain's
// camera port, sends a frame and closes; the socket, the clock and the capture
// stay in the kernel. `remote.rs` ends the control session through it, so it
// sits at the crate root.

#[allow(dead_code)]
#[path = "../../../../domains/robot/behavior/src/camera_tx.rs"]
mod camera_tx;

#[cfg(test)]
mod camera_tx_policy {
    use super::camera_tx::*;

    const UP: ControlSession = ControlSession { up: true, generation: 7 };
    const OK: Socket = Socket { established: true, carry_empty: true, stalled: false };

    fn inputs(now_ms: u64) -> Inputs {
        Inputs { now_ms, enabled: true, mode: LinkMode::Encrypted, control: UP }
    }

    fn connected(now_ms: u64) -> CameraTx {
        let mut tx = CameraTx::new();
        assert_eq!(tx.step(&inputs(now_ms), &OK), Step::Dial { generation: 7 });
        tx.dialed(7, now_ms);
        tx
    }

    /// Canary: drop the `enabled` check — it dials with no camera port.
    #[test]
    fn no_dial_without_a_camera_port() {
        let mut tx = CameraTx::new();
        let i = Inputs { enabled: false, ..inputs(0) };
        assert_eq!(tx.step(&i, &OK), Step::Wait { until_ms: POLL_MS });
    }

    /// Canary: drop the control check — it dials with no control session.
    #[test]
    fn no_dial_without_a_control_session() {
        let mut tx = CameraTx::new();
        let i = Inputs { control: ControlSession { up: false, generation: 7 }, ..inputs(0) };
        assert_eq!(tx.step(&i, &OK), Step::Wait { until_ms: POLL_MS });
    }

    /// The brain refuses a camera connection on an HMAC-only link, and no
    /// camera frame fits its plaintext reader. Canary: accept `HmacOnly` too.
    #[test]
    fn dials_only_with_rfc0019_armed() {
        for mode in [LinkMode::Unkeyed, LinkMode::HmacOnly] {
            let mut tx = CameraTx::new();
            let i = Inputs { mode, ..inputs(0) };
            assert_eq!(tx.step(&i, &OK), Step::Wait { until_ms: POLL_MS }, "{mode:?}");
        }
        let mut tx = CameraTx::new();
        assert_eq!(tx.step(&inputs(0), &OK), Step::Dial { generation: 7 });
    }

    /// Canary: drop the `control.up` check on a live connection.
    #[test]
    fn closes_when_the_control_session_ends() {
        let mut tx = connected(0);
        let i = Inputs { control: ControlSession { up: false, generation: 7 }, ..inputs(10) };
        assert_eq!(tx.step(&i, &OK), Step::Close(CloseReason::ControlEnded));
    }

    /// Control dropped and came back between two steps: the flag is up
    /// again, and only the generation tells. Canary: drop the generation
    /// compare.
    #[test]
    fn closes_when_a_new_control_session_replaces_its_own() {
        let mut tx = connected(0);
        let i = Inputs { control: ControlSession { up: true, generation: 8 }, ..inputs(10) };
        assert_eq!(tx.step(&i, &OK), Step::Close(CloseReason::ControlReplaced));
    }

    /// Canary: drop the Established check, or the stall check.
    #[test]
    fn closes_when_the_socket_drops_or_the_carry_stalls() {
        let mut tx = connected(0);
        let down = Socket { established: false, ..OK };
        assert_eq!(tx.step(&inputs(10), &down), Step::Close(CloseReason::NotEstablished));
        let stalled = Socket { carry_empty: false, stalled: true, ..OK };
        assert_eq!(tx.step(&inputs(10), &stalled), Step::Close(CloseReason::Stalled));
    }

    /// Canary: drop the `enabled` or the mode check on a live connection.
    #[test]
    fn closes_when_the_port_is_unset_or_rfc0019_is_disarmed() {
        let mut tx = connected(0);
        let off = Inputs { enabled: false, ..inputs(10) };
        assert_eq!(tx.step(&off, &OK), Step::Close(CloseReason::Disabled));
        let hmac = Inputs { mode: LinkMode::HmacOnly, ..inputs(10) };
        assert_eq!(tx.step(&hmac, &OK), Step::Close(CloseReason::NotEncrypted));
    }

    /// Canary: no doubling, or no cap.
    #[test]
    fn failed_dials_back_off_doubling_to_the_cap() {
        let mut tx = CameraTx::new();
        let mut now = 0;
        let mut waits = Vec::new();
        for _ in 0..8 {
            assert_eq!(tx.step(&inputs(now), &OK), Step::Dial { generation: 7 });
            tx.dial_failed(now);
            let Step::Wait { until_ms } = tx.step(&inputs(now), &OK) else {
                panic!("dialed again inside its back-off at {now} ms");
            };
            waits.push(until_ms - now);
            now = until_ms;
        }
        assert_eq!(waits, [1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000, 30_000]);
    }

    /// Canary: `closed` always backs off — the wait is 8 s, not 1 s.
    #[test]
    fn a_session_that_sent_a_frame_resets_the_back_off() {
        let mut tx = CameraTx::new();
        for now in [0, 1_000, 3_000] {
            assert_eq!(tx.step(&inputs(now), &OK), Step::Dial { generation: 7 });
            tx.dial_failed(now);
        }
        tx.dialed(7, 7_000);
        assert_eq!(tx.step(&inputs(7_000), &OK), Step::Frame);
        tx.frame_done(7_000, true);
        tx.closed(7_100);
        assert_eq!(tx.step(&inputs(7_100), &OK), Step::Wait { until_ms: 8_100 });
    }

    /// A brain that accepts and drops before any frame is not redialed every
    /// second. Canary: `closed` always resets — the wait is 1 s, not 2 s.
    #[test]
    fn a_session_that_sent_nothing_keeps_backing_off() {
        let mut tx = CameraTx::new();
        assert_eq!(tx.step(&inputs(0), &OK), Step::Dial { generation: 7 });
        tx.dial_failed(0);
        assert_eq!(tx.step(&inputs(1_000), &OK), Step::Dial { generation: 7 });
        tx.dialed(7, 1_000);
        tx.closed(1_050);
        assert_eq!(tx.step(&inputs(1_050), &OK), Step::Wait { until_ms: 3_050 });
    }

    /// Canary: `frame_done` leaves the schedule alone — a second frame at
    /// 450 ms.
    #[test]
    fn one_frame_per_period() {
        let mut tx = connected(0);
        assert_eq!(tx.step(&inputs(0), &OK), Step::Frame);
        tx.frame_done(0, true);
        assert_eq!(tx.step(&inputs(450), &OK), Step::Wait { until_ms: 500 });
        assert_eq!(tx.step(&inputs(500), &OK), Step::Frame);
        assert_eq!(tx.frames(), 1);
    }

    /// The frame due while the carry still holds the previous message is
    /// dropped, not sent the moment the carry empties. Canary: a busy carry
    /// leaves the schedule alone — a frame at 600 ms.
    #[test]
    fn a_busy_carry_skips_the_due_frame_instead_of_queueing_it() {
        let mut tx = connected(0);
        tx.frame_done(0, true);
        let busy = Socket { carry_empty: false, ..OK };
        assert_eq!(tx.step(&inputs(500), &busy), Step::Drain);
        assert_eq!(tx.step(&inputs(600), &OK), Step::Wait { until_ms: 700 });
        assert_eq!(tx.step(&inputs(1_000), &OK), Step::Frame);
    }

    /// The behavior task's handoff, and every link drop ending it through
    /// `remote_set_connected(false)`. One test: the word is process-wide.
    /// Canary: remove the `control_session_ended()` call from
    /// `remote_set_connected`.
    #[test]
    fn control_sessions_rise_and_every_link_drop_ends_them() {
        let start = control_session().generation;
        control_session_ready();
        assert_eq!(control_session(), ControlSession { up: true, generation: start + 1 });
        crate::remote::remote_set_connected(false);
        assert_eq!(control_session(), ControlSession { up: false, generation: start + 1 });
        control_session_ready();
        assert_eq!(control_session(), ControlSession { up: true, generation: start + 2 });
        control_session_ended();
        assert_eq!(control_session(), ControlSession { up: false, generation: start + 2 });
    }
}

#[cfg(test)]
mod brain_tx_carry {
    use super::brain_tx::{SealRefused, TxCarry};
    use std::cell::Cell;

    const STALL: u64 = 2_000;

    /// A socket that takes, per call, the next count in `script` (capped at
    /// what it is offered), and everything once the script runs out.
    struct Socket {
        script: Vec<usize>,
        calls: usize,
        wire: Vec<u8>,
    }

    impl Socket {
        fn new(script: &[usize]) -> Self {
            Socket { script: script.to_vec(), calls: 0, wire: Vec::new() }
        }

        fn send(&mut self, bytes: &[u8]) -> usize {
            let n = self.script.get(self.calls).copied().unwrap_or(bytes.len()).min(bytes.len());
            self.calls += 1;
            self.wire.extend_from_slice(&bytes[..n]);
            n
        }
    }

    fn seal(carry: &mut TxCarry<64>, now: u64, msg: &[u8]) -> Result<usize, SealRefused> {
        carry.seal_with(now, |out| {
            out[..msg.len()].copy_from_slice(msg);
            msg.len()
        })
    }

    fn message(tag: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| tag ^ i as u8).collect()
    }

    /// The socket takes nothing, then part, then nothing, then part, then the
    /// rest — as a full send window does. Every sealed byte must reach the
    /// wire once, in order, and the second message only after the first.
    #[test]
    fn every_sealed_byte_arrives_in_order_exactly_once_across_short_sends() {
        let mut carry = TxCarry::<64>::new();
        let mut sock = Socket::new(&[0, 5, 0, 3]);
        let clock = || 0u64;
        let (a, b) = (message(0xA0, 40), message(0x50, 17));
        let mut sealed = Vec::new();
        for msg in [&a, &b] {
            // One drain per behavior tick until the socket has it all.
            while !carry.is_empty() {
                carry.drain(|bytes| sock.send(bytes), clock, STALL);
            }
            seal(&mut carry, 0, msg).unwrap();
            sealed.extend_from_slice(msg);
            carry.drain(|bytes| sock.send(bytes), clock, STALL);
        }
        while !carry.is_empty() {
            carry.drain(|bytes| sock.send(bytes), clock, STALL);
        }
        assert_eq!(sock.wire, sealed, "a sealed byte was lost, repeated or reordered");
    }

    /// Each run of the sealer spends record counters. It must not run while
    /// the previous message is still partly unsent.
    #[test]
    fn nothing_is_sealed_while_a_remainder_is_pending() {
        let mut carry = TxCarry::<64>::new();
        let seals = Cell::new(0u32);
        let sealer = |out: &mut [u8]| {
            seals.set(seals.get() + 1);
            out[..8].copy_from_slice(&[7u8; 8]);
            8
        };
        let mut sock = Socket::new(&[3, 0]);
        assert_eq!(carry.seal_with(0, sealer), Ok(8));
        assert_eq!(carry.drain(|bytes| sock.send(bytes), || 0, STALL), 3);
        assert_eq!(carry.pending_len(), 5);

        assert_eq!(carry.seal_with(0, sealer), Err(SealRefused::Pending));
        assert_eq!(seals.get(), 1, "the sealer ran with 5 bytes of the last message unsent");
        assert_eq!(carry.pending_len(), 5, "the pending bytes must be untouched");

        carry.drain(|bytes| sock.send(bytes), || 0, STALL);
        assert!(carry.is_empty());
        assert_eq!(carry.seal_with(0, sealer), Ok(8));
        assert_eq!(seals.get(), 2);
        assert_eq!(sock.wire, vec![7u8; 8]);
    }

    /// No byte taken for the whole bound trips the stall; one tick less does
    /// not. A stall drops nothing — the caller ends the session instead.
    #[test]
    fn the_stall_trips_at_the_bound_and_not_before() {
        let mut carry = TxCarry::<64>::new();
        let now = Cell::new(1_000u64);
        seal(&mut carry, now.get(), &[1u8; 10]).unwrap();
        let refuse = |_: &[u8]| 0usize;

        now.set(1_000 + STALL - 1);
        carry.drain(refuse, || now.get(), STALL);
        assert!(!carry.is_stalled(), "tripped one tick before the bound");

        now.set(1_000 + STALL);
        carry.drain(refuse, || now.get(), STALL);
        assert!(carry.is_stalled(), "no byte taken for the whole bound, and no stall");
        assert_eq!(carry.pending_len(), 10);
    }

    /// Progress restarts the timer — and only progress does: the stall still
    /// trips a full bound after the last byte taken.
    #[test]
    fn progress_restarts_the_stall_timer() {
        let mut carry = TxCarry::<64>::new();
        let now = Cell::new(0u64);
        seal(&mut carry, 0, &[2u8; 10]).unwrap();
        let refuse = |_: &[u8]| 0usize;

        now.set(STALL - 1);
        let mut sock = Socket::new(&[4, 0]);
        assert_eq!(carry.drain(|bytes| sock.send(bytes), || now.get(), STALL), 4);

        now.set(STALL + 10);
        carry.drain(refuse, || now.get(), STALL);
        assert!(!carry.is_stalled(), "bytes taken at STALL-1 did not restart the timer");

        now.set(STALL - 1 + STALL);
        carry.drain(refuse, || now.get(), STALL);
        assert!(carry.is_stalled(), "no stall a full bound after the last byte taken");
    }
}

// ── Wave 15 (B1): the behavior task enqueues, `brain-tx` drains ───────────
#[cfg(test)]
mod brain_tx_queue {
    use super::brain_tx::{Lane, TxQueue};

    const STALL: u64 = 2_000;

    fn msg(tag: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| tag.wrapping_add(i as u8)).collect()
    }

    /// Telemetry can never take the room a control message needs: with the
    /// queue full up to the reserve, telemetry is refused (counted) and a
    /// control message is still admitted.
    #[test]
    fn telemetry_never_fills_the_control_reserve() {
        let mut q = TxQueue::<1024>::new(256);
        let mut n = 0;
        while q.push(Lane::Telemetry, &msg(1, 100), 0) {
            n += 1;
        }
        assert_eq!(n, 7, "7 x 100 B fit below the 256 B reserve of 1024");
        assert_eq!(q.telemetry_dropped, 1);
        assert!(q.admits(Lane::Control, 200));
        assert!(q.push(Lane::Control, &msg(2, 200), 0), "control refused behind telemetry");
        assert_eq!(q.control_refused, 0);
        assert_eq!(q.admitted, [1, 7]);
    }

    /// The canary bucket: with no reserve (the single-lane queue this
    /// replaces), telemetry fills the queue and the control message is
    /// refused — the property above is the reserve's, not the queue's.
    #[test]
    fn without_a_reserve_telemetry_starves_control() {
        let mut q = TxQueue::<1024>::new(0);
        while q.push(Lane::Telemetry, &msg(1, 100), 0) {}
        assert!(!q.push(Lane::Control, &msg(2, 200), 0));
        assert_eq!(q.control_refused, 1);
    }

    /// One FIFO of wire bytes: the order of admission is the order on the
    /// wire (sealed records may not be reordered), across the wrap, with a
    /// socket that takes odd amounts.
    #[test]
    fn bytes_leave_in_admission_order_across_the_wrap() {
        let mut q = TxQueue::<300>::new(50);
        let mut wire = Vec::new();
        let mut expect = Vec::new();
        let mut take = [7usize, 0, 13, 100, 1, 64].iter().cycle();
        for k in 0..40u8 {
            let lane = if k % 5 == 0 { Lane::Control } else { Lane::Telemetry };
            let m = msg(k, 37 + (k as usize * 11) % 60);
            if q.push(lane, &m, k as u64) {
                expect.extend_from_slice(&m);
            }
            q.drain(|b| { let n = (*take.next().unwrap()).min(b.len()); wire.extend_from_slice(&b[..n]); n }, || k as u64, STALL);
        }
        while !q.is_empty() {
            q.drain(|b| { wire.extend_from_slice(b); b.len() }, || 0, STALL);
        }
        assert_eq!(wire, expect);
    }

    /// A socket that takes nothing for the stall bound marks the queue
    /// stalled; any progress clears it.
    #[test]
    fn a_queue_the_socket_does_not_take_stalls() {
        let mut q = TxQueue::<512>::new(64);
        assert!(q.push(Lane::Control, &msg(3, 80), 100));
        assert_eq!(q.drain(|_| 0, || 100 + STALL - 1, STALL), 0);
        assert!(!q.is_stalled());
        q.drain(|_| 0, || 100 + STALL, STALL);
        assert!(q.is_stalled());
        q.drain(|b| b.len().min(10), || 100 + STALL + 1, STALL);
        assert!(!q.is_stalled(), "progress must clear the stall");
        assert_eq!(q.pending_len(), 0);
    }

    /// The stall clock starts at the push that made the queue non-empty,
    /// not at the last drain of an earlier, finished message.
    #[test]
    fn the_stall_clock_starts_at_the_first_queued_byte() {
        let mut q = TxQueue::<512>::new(64);
        assert!(q.push(Lane::Telemetry, &msg(4, 20), 0));
        q.drain(|b| b.len(), || 0, STALL);
        assert!(q.push(Lane::Telemetry, &msg(5, 20), 10 * STALL));
        q.drain(|_| 0, || 10 * STALL + 1, STALL);
        assert!(!q.is_stalled());
    }

    /// A new session forgets the bytes, keeps the per-boot counters.
    #[test]
    fn reset_forgets_bytes_not_counters() {
        let mut q = TxQueue::<256>::new(200);
        assert!(q.push(Lane::Telemetry, &msg(6, 50), 0));
        assert!(!q.push(Lane::Telemetry, &msg(6, 50), 0));
        q.reset();
        assert!(q.is_empty() && !q.is_stalled());
        assert_eq!(q.telemetry_dropped, 1);
        assert!(q.front().is_empty());
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Q1.3 / Q1.4 (owner decisions, 2026-09-25) — the actuation gate fails
// closed with no gate installed, and an admitted actuation command gets a
// bounded, rate-limited record.
// ═══════════════════════════════════════════════════════════════════════
//
// `domains/robot/robot/src/motor.rs` (the gate/record hooks) is the code under
// test, not a reimplementation — but unlike every other `#[path]`-pulled
// module in this file, it cannot be pulled directly into THIS crate: it
// needs `SpinLock::get_mut_unchecked` (`motor_stop_panic`'s panic-path
// escape hatch), which this crate's own `azos_sync` alias
// (`cap_test_sync`, used by `logger.rs`/`safety.rs`/everything else here)
// deliberately omits, and a crate can only have one `azos_sync`. So it
// lives in its own small dependency instead — `shims/robot`, a copy of
// `tests/host/syscall-tests/shims/robot`'s already-proven answer to this exact
// problem, with its own `shims/robot_sync`. See both crates' doc comments.

#[cfg(test)]
mod motor_gate_and_record {
    use azos_robot::motor_real as motor;
    use azos_robot::MotorDir;
    use std::sync::Mutex;

    /// One lock for `MOTOR_GATE`/`MOTOR_HALT`/`MOTOR_RECORD`/`MOTORS` —
    /// process-wide statics `cargo test` shares across threads, the same
    /// class of problem `tests/host/syscall-tests`' `harness::serial()` and this
    /// file's own `flight_recorder::SERIAL` already solve.
    static SERIAL: Mutex<()> = Mutex::new(());

    const WHEEL:   u32 = 0;
    const WHEEL_CH: u32 = 0;
    const PIN_A:   u32 = 10;
    const PIN_B:   u32 = 11;

    /// Fresh motor table entry, no gate, no halt, no recorder — the state a
    /// boot has before `azos_safety_core::actuation::install()` runs.
    fn begin() -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        motor::clear_motor_gate_for_test();
        motor::clear_motor_recorder_for_test();
        motor::set_motor_halt(|| false);
        assert_eq!(motor::motor_init(WHEEL, WHEEL_CH, PIN_A, PIN_B), 0);
        g
    }

    fn passthrough_gate(_id: u32, pct: u32) -> u32 { pct }

    // ── Q1.4: fail closed ────────────────────────────────────────────────

    /// **RED before / GREEN after.** Before 2026-09-25, `gate_speed`'s
    /// `None` arm returned `speed_pct` unchanged: a caller reaching
    /// `motor_set_reporting` before boot finished installing the gate got
    /// full authority, not none. Revert `gate_speed`'s `None => 0`
    /// (`domains/robot/robot/src/motor.rs`) to `None => speed_pct` and this fails
    /// — `applied` comes back `Some(77)`.
    #[test]
    fn no_gate_installed_clamps_every_speed_to_zero_not_passthrough() {
        let _g = begin();
        assert!(!motor::motor_gate_installed());
        let (rc, applied) = motor::motor_set_reporting(WHEEL, MotorDir::Forward, 77);
        assert_eq!(rc, 0, "not refused — clamped");
        assert_eq!(applied, Some(0), "gate absent must clamp to 0, not pass 77 through");
        assert_eq!(motor::motor_state(WHEEL), Some((MotorDir::Forward, 0)));
    }

    /// The flip did not remove the gate itself: an INSTALLED gate still
    /// decides the duty, unclamped by the absent-gate default — so the
    /// fail-closed change is a change to the DEFAULT, not to the mechanism.
    #[test]
    fn an_installed_gate_still_decides_the_duty() {
        let _g = begin();
        motor::set_motor_gate(passthrough_gate);
        assert!(motor::motor_gate_installed());
        let (rc, applied) = motor::motor_set_reporting(WHEEL, MotorDir::Forward, 77);
        assert_eq!(rc, 0);
        assert_eq!(applied, Some(77));
    }

    // ── Q1.3: record on change, not on repeat ───────────────────────────

    static SEEN: Mutex<Vec<(u32, MotorDir, u32)>> = Mutex::new(Vec::new());

    fn test_recorder(id: u32, dir: MotorDir, speed_pct: u32) {
        SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((id, dir, speed_pct));
    }

    fn seen() -> Vec<(u32, MotorDir, u32)> {
        SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// **RED before / GREEN after, both halves.** Before this hook existed
    /// a SUCCESSFUL motor command left no record at all —
    /// `motor_set_reporting` had nothing to call, so the first assertion
    /// fails against the pre-fix tree (nothing to `assert_eq!` against an
    /// empty `seen()`).
    ///
    /// **Canary for "on change, not on every write".** Change
    /// `motor_set_reporting`'s `if changed { record_motor_change(...) }` to
    /// call unconditionally: the second assertion fails, because the
    /// repeat is recorded too (`seen().len() == 2`, not `1`).
    #[test]
    fn a_change_is_recorded_but_a_repeat_is_not() {
        let _g = begin();
        motor::set_motor_gate(passthrough_gate);
        motor::set_motor_recorder(test_recorder);
        SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();

        motor::motor_set_reporting(WHEEL, MotorDir::Forward, 40);
        assert_eq!(seen(), vec![(WHEEL, MotorDir::Forward, 40)], "a change must be recorded");

        motor::motor_set_reporting(WHEEL, MotorDir::Forward, 40);
        assert_eq!(seen().len(), 1, "a repeat of the same command must not add a second record");

        motor::motor_set_reporting(WHEEL, MotorDir::Forward, 41);
        assert_eq!(seen().len(), 2, "a real change after a repeat must still be recorded");
    }

    /// A refusal while halted still changes the applied duty (e.g. 40 -> 0),
    /// and that change is recorded too — "what was it doing right before
    /// the latch" is exactly the question this leg answers, not only the
    /// admitted-command leg above.
    #[test]
    fn a_halt_induced_drop_to_zero_is_recorded_once_not_on_repeat() {
        let _g = begin();
        motor::set_motor_gate(passthrough_gate);
        motor::set_motor_recorder(test_recorder);

        // Drive to 40% with the halt off, then arm the halt and observe the
        // forced drop to 0.
        motor::motor_set_reporting(WHEEL, MotorDir::Forward, 40);
        SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
        motor::set_motor_halt(|| true);

        let (rc, applied) = motor::motor_set_reporting(WHEEL, MotorDir::Forward, 60);
        assert_eq!(rc, motor::MOTOR_REFUSED_HALTED);
        assert_eq!(applied, Some(0));
        assert_eq!(seen(), vec![(WHEEL, MotorDir::Forward, 0)], "the 40->0 drop must be recorded once");

        SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
        motor::motor_set_reporting(WHEEL, MotorDir::Forward, 60);
        assert!(seen().is_empty(), "already at 0 — a repeated refusal must not record again");

        motor::set_motor_halt(|| false);
    }
}

#[cfg(test)]
mod motor_actuation_reaches_the_flight_recorder {
    //! Q1.3's other half: once a change is admitted, it must actually reach
    //! the bounded ring and — through the watchdog's EXISTING periodic
    //! flush — disk, with no second durable path invented for it.
    //! `domains/robot/safety-core/src/actuation.rs`'s `record_motor_change` hook
    //! calls exactly `log_actuator_cmd`, after `domains/robot/robot`'s own
    //! on-change filter (`motor_gate_and_record`, above); this suite
    //! exercises `log_actuator_cmd` itself, the function both that hook and
    //! any future caller go through.
    use super::logger::*;
    use super::log_storage_mock as fsmock;
    use super::flight_recorder::begin;

    /// **RED before / GREEN after.** Before 2026-09-25 `log_actuator_cmd`
    /// had zero callers anywhere in the tree (`grep -rn log_actuator_cmd`),
    /// so a successful motor command reached no recorder and this ring
    /// stayed empty for the life of a boot — the first assertion below has
    /// nothing to be equal to `LOG_RING_CAPACITY` against a pre-fix tree
    /// that never calls this function outside a test. It is the SAME ring
    /// `log_safety_violation` uses, so a burst past capacity drops the
    /// oldest motor record exactly as it drops the oldest safety record —
    /// proved directly here rather than assumed from that other test.
    #[test]
    fn a_motor_command_reaches_the_bounded_ring_and_drops_the_oldest_past_capacity() {
        let _g = begin(0x1000);
        let _ = logger_init();

        for i in 0..(LOG_RING_CAPACITY + 5) {
            log_actuator_cmd(0, (i % 4) as i16, (i % 101) as i16, 0, 0);
        }
        assert_eq!(logger_ring_len(), LOG_RING_CAPACITY, "the ring is bounded for actuator records too");
        assert_eq!(logger_analytics().events_dropped, 5, "5 pushed past capacity must be counted dropped");

        logger_shutdown();
    }

    /// A record's payload carries the values back out whole, so a readback
    /// finds the actual commanded numbers — "read a number back where one
    /// exists" — not just the event-kind byte.
    #[test]
    fn a_motor_record_carries_its_id_and_effective_speed_back_out() {
        let _g = begin(0x2000);
        let _ = logger_init();

        log_actuator_cmd(1, 0 /* Forward */, 73, 0, 0);
        let _ = logger_flush();

        assert_eq!(fsmock::file_count(), 1);
        let bytes = fsmock::file_bytes(0);
        assert!(bytes.len() >= LOG_FILE_HEADER_BYTES + LOG_RECORD_SIZE);
        let mut raw = [0u8; LOG_RECORD_SIZE];
        raw.copy_from_slice(&bytes[LOG_FILE_HEADER_BYTES .. LOG_FILE_HEADER_BYTES + LOG_RECORD_SIZE]);
        let rec = LogRecord::decode(&raw);
        assert_eq!(rec.kind, LOG_EVT_ACTUATOR_CMD);
        assert_eq!(rec.payload[0], 1, "actuator_type carries the motor id");
        let ch1 = i16::from_le_bytes([rec.payload[4], rec.payload[5]]);
        assert_eq!(ch1, 73, "ch1 carries the effective speed");

        logger_shutdown();
    }
}

// ---------------------------------------------------------------------------
// Entropy-refusal policy (`domains/robot/behavior/src/encrypt_link_policy.rs`),
// U09-8 / owner decision 2026-09-26 V1.2.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[path = "../../../../domains/robot/behavior/src/encrypt_link_policy.rs"]
mod encrypt_link_policy;

/// RED test for "unseeded ⇒ no session keys". This is the exact boolean
/// `domains/robot/behavior/src/encrypt_link.rs`'s `derive_ephemeral_priv` gates on
/// before deriving anything — pulled in by `#[path]` so this is the code
/// under test, not a restatement of it.
#[cfg(test)]
mod encrypt_link_unseeded_refusal {
    use super::encrypt_link_policy::refuse_unseeded;

    /// RED against the code as it stood before the 2026-09-26 V1.2 decision:
    /// `derive_ephemeral_priv` had no refusal path at all — every call
    /// returned a key, degraded, regardless of `seeded`/`enforced`.
    /// Restoring that (an always-`false` `refuse_unseeded`) fails this.
    #[test]
    fn unseeded_on_an_enforced_build_refuses() {
        assert!(refuse_unseeded(false, true),
            "an unseeded pool on a link-encrypt-enforced build must refuse — \
             this is what stops a VF2/K1 from ever deriving a session key from \
             PSK + boot-relative timing alone");
    }

    #[test]
    fn seeded_never_refuses_regardless_of_enforcement() {
        assert!(!refuse_unseeded(true, true));
        assert!(!refuse_unseeded(true, false));
    }

    #[test]
    fn unseeded_on_a_dev_build_still_proceeds_degraded() {
        // The accepted dev/QEMU tradeoff, unchanged by this decision: no
        // prod key rolled out yet means no enforcement, and an unseeded
        // dev board still gets a (weak) handshake rather than none.
        assert!(!refuse_unseeded(false, false));
    }
}

// ---------------------------------------------------------------------------
// The ML service's verdict, and its absence (`ml_link`). The MLP runs in the
// ring-3 ML service; a cycle whose verdict does not come must still decide,
// and must decide STOP through L1 — never pass to L2/L3 blind.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod ml_verdict {
    use super::arbiter::*;
    use super::ml_link::*;
    use super::types::*;

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        super::envelope::serial()
    }

    #[test]
    fn a_verdict_is_passed_through_unchanged() {
        for c in 0..CLASSES {
            let r = mlp_result_for(MlOutcome::Verdict(c));
            assert!(r.valid);
            assert_eq!(r.class, c);
        }
    }

    /// Late, gone and garbled are one case: a verdict was expected and there
    /// is none to act on. (`--features ml-fallback-canary` must fail this.)
    #[test]
    fn every_missing_verdict_is_stop() {
        for o in [MlOutcome::Late, MlOutcome::Unavailable, MlOutcome::Malformed,
                  MlOutcome::Verdict(CLASSES), MlOutcome::Verdict(0xFF)] {
            let r = mlp_result_for(o);
            assert!(r.valid, "{:?} must still decide", o);
            assert_eq!(r.class, CLASS_STOP, "{:?} must decide STOP", o);
        }
    }

    /// Owner decision 2026-09-28, fail closed: a boot that never started the
    /// service holds STOP like one whose service died. (`--features
    /// ml-absent-canary` must fail this.)
    #[test]
    fn never_launched_is_stop() {
        let r = mlp_result_for(MlOutcome::NotLaunched);
        assert!(r.valid, "a service that never started must still decide");
        assert_eq!(r.class, CLASS_STOP, "and decide STOP");
    }

    /// The fallback through the real arbiter: L1 wins and commands (0, 0), on
    /// the fixture where nothing else would win at all. Same baseline as the
    /// `arbitration` suite, whose statics this shares.
    #[test]
    fn the_fallback_stops_the_robot_through_l1() {
        use super::safety::*;
        let _g = serial();
        estop_release(ReleaseAuthority::for_test());
        safety_set_robot_type(ROBOT_TYPE_WHEELED);
        geofence_disable();
        super::offline::offline_deactivate();
        for l in 0..NUM_LAYERS {
            layer_set_enabled(l, true);
        }
        super::safety::test_reset_imu_incoherence();
        super::camera_tx::control_session_ended();
        for o in [MlOutcome::Unavailable, MlOutcome::NotLaunched] {
            let out = arbitrate(&SensorState::new(), &mlp_result_for(o));
            assert_eq!(out.layer, 1, "the missing verdict ({o:?}) must be decided by L1");
            assert!(out.cmd.valid, "and applied ({o:?})");
            assert_eq!((out.cmd.speed_l, out.cmd.speed_r), (0, 0), "{o:?}");
        }
    }

    #[test]
    fn stats_count_each_outcome_once() {
        let mut s = MlLinkStats::new();
        for o in [MlOutcome::Verdict(0), MlOutcome::Verdict(2), MlOutcome::Late,
                  MlOutcome::Unavailable, MlOutcome::Malformed, MlOutcome::Verdict(7),
                  MlOutcome::NotLaunched] {
            s.note(o);
        }
        assert_eq!(s, MlLinkStats { verdicts: 2, late: 1, unavailable: 1, malformed: 2, not_launched: 1 });
        assert_eq!(s.fallbacks(), 5);
    }

    /// Drive `MlAbsence` the way the loop does: each outcome through
    /// `mlp_result_for` first. Returns the cycles (0-based) that recorded.
    fn records(outcomes: &[MlOutcome]) -> Vec<(usize, u8)> {
        let mut a = MlAbsence::new();
        outcomes.iter().enumerate()
            .filter_map(|(i, &o)| a.note(o, &mlp_result_for(o)).map(|act| (i, act)))
            .collect()
    }

    /// A service that never started is recorded once, on the
    /// `ABSENT_RECORD_CYCLES`-th cycle, and not again however long it lasts.
    /// (`--features ml-absent-canary` must fail this: nothing is recorded.)
    #[test]
    fn a_service_that_never_started_is_recorded_once() {
        let n = ABSENT_RECORD_CYCLES as usize;
        let got = records(&vec![MlOutcome::NotLaunched; 5 * n]);
        assert_eq!(got, vec![(n - 1, ABSENT_NOT_LAUNCHED)]);
    }

    /// The start-up gap (the service not yet registered for a cycle or two)
    /// is not an absence; a service that dies after answering is, once per
    /// episode, with the outcome of the recording cycle.
    #[test]
    fn a_short_gap_is_not_recorded_and_each_episode_is() {
        let n = ABSENT_RECORD_CYCLES as usize;
        let mut seq = vec![MlOutcome::Unavailable; n - 1];
        seq.push(MlOutcome::Verdict(0));
        seq.extend(vec![MlOutcome::Late; 3]);
        seq.extend(vec![MlOutcome::Unavailable; n - 3]);
        seq.push(MlOutcome::Verdict(1));
        seq.extend(vec![MlOutcome::Malformed; n]);
        let first = n;
        let second = first + n + 1;
        assert_eq!(records(&seq), vec![(first + n - 1, ABSENT_UNAVAILABLE),
                                       (second + n - 1, ABSENT_MALFORMED)]);
    }

    /// A cycle L1 did not hold STOP on is neither recorded nor counted: the
    /// record claims STOP was held.
    #[test]
    fn no_record_without_the_stop_it_claims() {
        let mut a = MlAbsence::new();
        for _ in 0..3 * ABSENT_RECORD_CYCLES {
            assert_eq!(a.note(MlOutcome::Unavailable, &MlpResult::none()), None);
        }
        assert_eq!(absent_action(MlOutcome::Verdict(CLASSES)), Some(ABSENT_MALFORMED));
        assert_eq!(absent_action(MlOutcome::Verdict(CLASS_STOP)), None);
    }
}


// ---------------------------------------------------------------------------
// Wave 15: the boot arms the fence at the home fix (`safety::geofence_arm_home`).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod geofence_home_arm {
    use super::safety::*;
    use super::types::*;

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        super::envelope::serial()
    }

    fn fix(q: u8, sats: u8, lat: i32, lon: i32) -> SensorState {
        let mut s = SensorState::new();
        s.gps_fix = q;
        s.gps_satellites = sats;
        s.gps_lat_udeg = lat;
        s.gps_lon_udeg = lon;
        s
    }

    fn reset() {
        estop_release(ReleaseAuthority::for_test());
        safety_set_robot_type(ROBOT_TYPE_WHEELED);
        test_reset_imu_incoherence();
        geofence_test_reset();
    }

    /// The first trusted fix arms a fence of `GEOFENCE_RADIUS_M` around it:
    /// a position past the radius is then Outside, one inside is Inside.
    #[test]
    fn the_first_trusted_fix_arms_the_fence_around_it() {
        let _g = serial();
        reset();
        let home = fix(1, GEOFENCE_MIN_SATELLITES, 48_135_100, 11_582_000);
        assert_eq!(geofence_arm_home(&home), Some((48_135_100, 11_582_000, 100)));
        assert!(geofence_armed());
        assert_eq!(geofence_status(&home), GeofenceStatus::Inside);
        // 0.009 deg north ~= 1 km: outside a 100 m fence.
        let away = fix(1, GEOFENCE_MIN_SATELLITES, 48_144_100, 11_582_000);
        assert_eq!(geofence_status(&away), GeofenceStatus::Outside);
        reset();
    }

    /// No arm on an untrusted fix: a simulated quality (8), or too few
    /// satellites. The fence stays disabled and the arm is not spent.
    #[test]
    fn an_untrusted_fix_does_not_arm() {
        let _g = serial();
        reset();
        assert_eq!(geofence_arm_home(&fix(8, 9, 1, 1)), None);
        assert_eq!(geofence_arm_home(&fix(1, GEOFENCE_MIN_SATELLITES - 1, 1, 1)), None);
        assert!(!geofence_armed());
        assert!(geofence_arm_home(&fix(1, GEOFENCE_MIN_SATELLITES, 1, 1)).is_some());
        reset();
    }

    /// Once per boot: a later fix does not move the centre, and an operator's
    /// disable after the arm stays disabled.
    #[test]
    fn the_home_arm_happens_once() {
        let _g = serial();
        reset();
        assert!(geofence_arm_home(&fix(1, 8, 0, 0)).is_some());
        assert_eq!(geofence_arm_home(&fix(1, 8, 5_000_000, 0)), None);
        geofence_disable();
        assert_eq!(geofence_arm_home(&fix(1, 8, 0, 0)), None);
        assert!(!geofence_armed());
        reset();
    }

    /// A fence configured explicitly before the first fix stands: the home
    /// arm is spent without moving it.
    #[test]
    fn an_explicit_fence_is_not_overwritten() {
        let _g = serial();
        reset();
        geofence_set(0, 0, 10);
        assert_eq!(geofence_arm_home(&fix(1, 8, 48_000_000, 11_000_000)), None);
        assert_eq!(geofence_status(&fix(1, 8, 0, 0)), GeofenceStatus::Inside);
        reset();
    }

    /// The breach latch on top of the home arm: the e-stop latches once and
    /// the record's distance is the overshoot.
    #[test]
    fn a_breach_of_the_home_fence_latches_once() {
        let _g = serial();
        reset();
        assert!(geofence_arm_home(&fix(1, 8, 48_135_100, 11_582_000)).is_some());
        let away = fix(1, 8, 48_144_100, 11_582_000);
        let first = geofence_breach_latch(&away);
        assert!(matches!(first, Some(m) if m > 800 && m < 1000), "{:?}", first);
        assert!(estop_is_active());
        assert_eq!(geofence_breach_latch(&away), None, "one record per breach");
        reset();
    }
}

// ---------------------------------------------------------------------------
// Wave 15: the RC receiver's safety policy (`domains/robot/behavior/src/rc_link.rs`).
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[path = "../../../../domains/robot/behavior/src/rc_link.rs"]
mod rc_link;

#[cfg(test)]
mod rc_link_policy {
    use super::rc_link::*;

    /// 1 MHz timer: one tick per microsecond, 1000 per ms.
    const POLICY: RcPolicy = RcPolicy::from_limits(1_000_000);

    fn sticks(set: &[(usize, u16)]) -> [u16; 16] {
        let mut c = [1500u16; 16];
        c[4] = 1000; // mode switch off
        c[5] = 1000; // kill switch off
        for &(ch, us) in set { c[ch - 1] = us; }
        c
    }

    #[test]
    fn the_policy_comes_from_kconfig() {
        assert_eq!(POLICY.link_timeout_ticks, 500_000);
        assert_eq!((POLICY.mode_channel, POLICY.kill_channel), (5, 6));
        assert_eq!((POLICY.drive_channel, POLICY.steer_channel), (2, 1));
    }

    /// No frame ever: the receiver has no say, whatever else is reported.
    #[test]
    fn no_link_before_the_first_frame() {
        assert_eq!(rc_evaluate(&POLICY, false, None, 0, 10_000_000), RcVerdict::NoLink);
        assert_eq!(rc_evaluate(&POLICY, false, Some((sticks(&[]), true)), 0, 10_000_000),
                   RcVerdict::NoLink);
    }

    /// The receiver's failsafe bit is link loss at once (detail 0).
    #[test]
    fn the_receiver_failsafe_bit_is_link_loss() {
        let v = rc_evaluate(&POLICY, true, Some((sticks(&[]), true)), 1000, 1000);
        assert_eq!(v, RcVerdict::LinkLoss { age_ms: None });
        assert_eq!(link_loss_detail(None), 0);
    }

    /// A frame older than the timeout is link loss with its age; one at the
    /// timeout is not.
    #[test]
    fn a_silent_link_times_out() {
        let at = rc_evaluate(&POLICY, true, Some((sticks(&[]), false)), 0, 500_000);
        assert_eq!(at, RcVerdict::Passive);
        let past = rc_evaluate(&POLICY, true, Some((sticks(&[]), false)), 0, 700_000);
        assert_eq!(past, RcVerdict::LinkLoss { age_ms: Some(700) });
        assert_eq!(link_loss_detail(Some(700)), 700);
    }

    /// A driver that stopped handing out data after a link existed is loss.
    #[test]
    fn a_driver_gone_quiet_after_a_link_is_loss() {
        assert_eq!(rc_evaluate(&POLICY, true, None, 0, 0), RcVerdict::LinkLoss { age_ms: None });
    }

    /// The kill switch outranks the mode switch.
    #[test]
    fn the_kill_switch_latches_over_manual() {
        let c = sticks(&[(6, 1900), (5, 2000), (2, 2000)]);
        assert_eq!(rc_evaluate(&POLICY, true, Some((c, false)), 0, 0),
                   RcVerdict::Kill { pulse_us: 1900 });
        let at = sticks(&[(6, 1700)]);
        assert_eq!(rc_evaluate(&POLICY, true, Some((at, false)), 0, 0), RcVerdict::Passive,
                   "at the threshold is not above it");
    }

    /// Mode switch on: full forward asks full scale on both sides; full
    /// right steer spins in place; centred sticks within the deadband ask 0.
    #[test]
    fn manual_mode_mixes_the_sticks() {
        let fwd = sticks(&[(5, 2000), (2, 2000)]);
        assert_eq!(rc_evaluate(&POLICY, true, Some((fwd, false)), 0, 0),
                   RcVerdict::Manual { left: 100, right: 100 });
        let spin = sticks(&[(5, 2000), (1, 2000)]);
        assert_eq!(rc_evaluate(&POLICY, true, Some((spin, false)), 0, 0),
                   RcVerdict::Manual { left: 100, right: -100 });
        let near = sticks(&[(5, 2000), (2, 1515), (1, 1485)]);
        assert_eq!(rc_evaluate(&POLICY, true, Some((near, false)), 0, 0),
                   RcVerdict::Manual { left: 0, right: 0 });
        let mode_off = sticks(&[(2, 2000)]);
        assert_eq!(rc_evaluate(&POLICY, true, Some((mode_off, false)), 0, 0), RcVerdict::Passive);
    }

    #[test]
    fn stick_scaling_and_mixing_are_bounded() {
        assert_eq!(stick_pct(1000, 20, 100), -100);
        assert_eq!(stick_pct(1750, 20, 100), 50);
        assert_eq!(stick_pct(2000, 0, 60), 60);
        assert_eq!(mix(100, 100, 100), (100, 0));
        assert_eq!(mix(-80, 50, 100), (-30, -100));
    }

    /// Channel 0 means "none": no kill switch, no manual mode.
    #[test]
    fn channel_zero_disables_a_switch() {
        let p = RcPolicy { kill_channel: 0, mode_channel: 0, ..POLICY };
        let c = sticks(&[(6, 2000), (5, 2000)]);
        assert_eq!(rc_evaluate(&p, true, Some((c, false)), 0, 0), RcVerdict::Passive);
    }
}
