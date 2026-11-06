// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The effect interface every profile has (`effect.rs`): an effect of a kind
//! no installed provider owns is refused with a receipt, a stop included (the
//! image has no such device), and one a provider owns is admitted with none.

use crate::effect::admit_kind;
use crate::ext_conformance::fresh;
use crate::kind::{Class, KIND_CLOCK, KIND_MOTOR};
use crate::providers;
use azos_decision::{Record, Rule, Verdict};
use azos_ext_api::{Manifest, Provider, API_LEVEL};

static WHEELS: Manifest = Manifest {
    name: "wheels",
    api_level: API_LEVEL,
    providers: &[Provider { name: "wheels", kinds: &[KIND_MOTOR], stop: || {}, panic_stop: || {}, on_latch: None, ready: None }],
    hooks: &[],
};

/// The `EffectUnserved` records of task `tid`.
fn unserved_of(tid: u32) -> Vec<Record> {
    let mut v = Vec::new();
    azos_decision::for_each(|r| {
        if r.rule == Rule::EffectUnserved as u8 && r.subject == tid {
            v.push(*r);
        }
    });
    v
}

/// **Canary.** Make `admit_kind` answer `Ok` for every kind: red.
#[test]
fn an_effect_of_a_kind_no_provider_owns_is_refused_with_a_receipt() {
    let _g = fresh();
    const TID: u32 = 4_201;
    let receipt = admit_kind(KIND_MOTOR, Class::Reversible, 3, TID).expect_err("no provider owns the motor kind");
    let rec = azos_decision::lookup(receipt).expect("the receipt is a decision record");
    assert_eq!((rec.rule, rec.verdict, rec.subject), (Rule::EffectUnserved as u8, Verdict::Refuse as u8, TID));
    assert_eq!(rec.n, [(KIND_MOTOR as u64) << 8 | Class::Reversible as u64, 3, 0]);
    assert!(admit_kind(KIND_MOTOR, Class::Safe, 3, TID).is_err(), "a stop of a wheel the image has not");
    assert_eq!(unserved_of(TID).len(), 2, "one receipt per refused effect");
}

/// **Canary.** Make `providers::serves` ignore the provider's kinds: red.
#[test]
fn an_effect_of_a_kind_a_provider_owns_is_admitted_without_a_record() {
    let _g = fresh();
    const TID: u32 = 4_202;
    providers::install(&WHEELS);
    assert_eq!(admit_kind(KIND_MOTOR, Class::Reversible, 0, TID), Ok(()));
    assert_eq!(admit_kind(KIND_MOTOR, Class::Safe, 1, TID), Ok(()));
    assert!(unserved_of(TID).is_empty(), "an admitted effect wrote a refusal");
    assert!(admit_kind(KIND_CLOCK, Class::Reversible, 0, TID).is_err(), "a kind the provider does not own");
}
