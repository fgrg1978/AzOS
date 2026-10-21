// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The SoC resource frameworks' effect kinds (2..6) through the write-ahead
//! gate: `effect_gate::record` commits a clock, reset, rail, pin-mux or
//! power-domain change to the flight recorder's ring before the framework
//! writes its register, and refuses a change the ring cannot hold, with a
//! receipt, except one toward quiescence.
//!
//! The framework half (the manager calls the sink before it writes) is
//! `tests/host/soc-tests`; the kernel's sink (`kernel/src/boot/soc.rs`) is the
//! few lines between the two.
//!
//! Canary: `effect-issue-before-commit-canary` does not discriminate here.
//! `record` runs no device op of its own, so there is no order inside the
//! gate to invert; the order is the manager's, and its canary is
//! `effect-after-write-canary` in soc-tests.

use crate::effect_gate::{self, Class, Effect, Why, KIND_CLOCK, KIND_PINCTRL, KIND_POWER_DOMAIN, KIND_REGULATOR, KIND_RESET};
use crate::logger::*;
use crate::medium;
use crate::tests::fresh;

const KINDS: [u8; 5] = [KIND_CLOCK, KIND_RESET, KIND_REGULATOR, KIND_PINCTRL, KIND_POWER_DOMAIN];

fn soc(kind: u8, class: Class, tag: u32) -> Effect {
    // subject: provider 1 in the high byte, op 3 in the low one (`Effect::wire`).
    Effect { kind, class, subject: 1 << 8 | 3, tid: 0, a0: tag, a1: 1_500_000 }
}

fn durable_effects() -> Vec<Effect> {
    let mut out = Vec::new();
    for f in medium::durable() {
        for rec in f.get(LOG_FILE_HEADER_BYTES..).unwrap_or(&[]).chunks_exact(LOG_RECORD_SIZE) {
            let r = LogRecord::decode(rec.try_into().unwrap());
            if r.kind == LOG_EVT_ACTUATOR_CMD && r.flags == LOG_FLAG_EFFECT {
                out.push(Effect::from_payload(&r.payload).expect("a known class"));
            }
        }
    }
    out
}

#[test]
fn the_soc_kinds_are_the_reserved_numbers_and_not_the_motors() {
    assert_eq!(KINDS, [2, 3, 4, 5, 6]);
    assert!(KINDS.iter().all(|&k| k != effect_gate::KIND_MOTOR));
}

#[test]
fn a_soc_change_is_on_the_ring_when_the_gate_returns_and_reaches_the_medium_whole() {
    let _g = fresh();
    let sent: Vec<Effect> = KINDS
        .iter()
        .enumerate()
        .map(|(i, &k)| soc(k, if i % 2 == 0 { Class::Reversible } else { Class::Safe }, 10 + i as u32))
        .collect();
    for (i, e) in sent.iter().enumerate() {
        let before = logger_ring_len();
        effect_gate::record(e).expect("a ring with room takes it");
        assert_eq!(logger_ring_len(), before + 1, "kind {}: the register write would come before its record", e.kind);
        assert_eq!(i + 1, logger_ring_len());
    }
    logger_flusher_pass();
    assert_eq!(durable_effects(), sent, "a record was lost, reordered or changed on its way to the medium");
}

#[test]
fn a_full_ring_refuses_a_soc_change_with_a_receipt_but_never_one_toward_quiescence() {
    let _g = fresh();
    let limit = LOG_RING_CAPACITY - RING_SAFETY_RESERVE;
    for i in 0..limit as u32 {
        effect_gate::record(&soc(KIND_CLOCK, Class::Reversible, i)).expect("under the limit");
    }
    // Switching something ON is refused, with a receipt the operator can look up.
    let r = effect_gate::record(&soc(KIND_CLOCK, Class::Reversible, 9999)).expect_err("the ring is at its limit");
    assert_eq!(r.why, Why::RingFull);
    let rec = azos_decision::lookup(r.receipt).expect("the receipt is a decision record");
    assert_eq!(rec.rule, azos_decision::Rule::EffectRecord as u8);
    assert_eq!(rec.n[0], (KIND_CLOCK as u64) << 8 | Class::Reversible as u64);
    // Gating a clock, asserting a reset, cutting a rail, powering a domain
    // off is never refused: a task that may switch it on can switch it off.
    for k in KINDS {
        effect_gate::record(&soc(k, Class::Safe, 7)).expect("a change toward quiescence is never refused");
    }
}

#[test]
fn a_soc_kind_is_never_held_by_the_motor_safe_state_table() {
    let _g = fresh();
    for k in KINDS {
        // Every subject a wire word can be: provider 0 gives 0..255 (the ones
        // the held mask could alias), the higher providers give the rest.
        for subject in (0u16..=0x0FFF).chain([0x1FF, 0x7FFF, 0xFFFF]) {
            assert!(!crate::safe_state::held(k, subject), "kind {k} subject {subject}");
        }
        assert!(!crate::safe_state::can_drive(k), "no safe-state driver is registered for kind {k}: nothing is watched");
    }
}

#[test]
fn the_safe_state_tables_stop_below_the_soc_kinds() {
    use crate::safe_state::MAX_KINDS;
    assert_eq!(MAX_KINDS, effect_gate::KIND_MOTOR as usize + 1);
    for k in KINDS {
        assert!(k as usize >= MAX_KINDS, "kind {k} would index a held mask or a driver slot");
    }
}
