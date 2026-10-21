// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for provenance-attenuated envelopes (innovation B4), the
//! effect gate's half: `effect_gate.rs` holds a reversible effect to the MEET
//! of the envelopes of every principal kind in the label of the data behind
//! it. The label half (the send ORs the sender's principal, the scope, the
//! per-kind envelope table) is tested where the code lives
//! (`crates/core/ipc/src/endpoint.rs`, `label` module); the probe here is a
//! model of it with the same arithmetic: a label is a set of principal kinds
//! (bit 1 a service, bit 3 an agent) and a kind has an envelope level.
//!
//! The scene of the test names: a planner (a `service` class, envelope
//! `full`) forwards what the LLM brain (an `agent` class, envelope `slow`)
//! said. The planner is fully rated; the effect it issues is still held to the
//! brain's slow envelope.
//!
//! **Canary.** Delete the `within` test in `issue`: the refusals below go red.
//! Make `within` compare against the issuer's own level (`level 0`): the
//! planner-through-the-brain test goes red while the plain ones stay green.

use crate::effect_gate::{self, Class, Effect, Timing, Why, KIND_CLOCK, KIND_MOTOR};
use crate::logger::*;
use crate::tests::fresh;
use azos_decision::{Rule, Verdict};
use std::sync::atomic::{AtomicU32, Ordering};

const SERVICE: u32 = 1 << 1;
const AGENT: u32 = 1 << 3;
/// Envelope levels, `Full` to `Contained`.
const SLOW: u8 = 2;

/// The devices of this scene: a wheel and a clock no other suite uses (the
/// receipt index and the held mask are process state).
const WHEEL: u16 = 30;
const CLOCK: u16 = 31;

/// Tasks of this scene: the planner forwards the brain's data, the plain one
/// works on its own, the third is a service that only ever saw the brain's
/// word through a channel the test sets.
const PLANNER: u32 = 0xB4_0001;
const PLAIN: u32 = 0xB4_0002;
const BRAIN: u32 = 0xB4_0003;

/// The model of `endpoint::label::provenance_of`: per task, the label of the
/// data it works on; per kind, an envelope level (service `full`, agent `slow`).
fn probe(tid: u32) -> (u32, u8) {
    let label = match tid {
        PLANNER => SERVICE | AGENT,
        PLAIN => SERVICE,
        BRAIN => AGENT,
        _ => 0,
    };
    let level = |bit: u32| if bit & AGENT != 0 { SLOW } else { 0 };
    let meet = [SERVICE, AGENT].iter().filter(|b| label & **b != 0).map(|b| level(*b)).max().unwrap_or(0);
    (label, meet)
}

fn motor(tid: u32, class: Class, duty: u32) -> Effect {
    Effect { kind: KIND_MOTOR, class, subject: WHEEL, tid, a0: 1, a1: duty }
}

fn run(e: &Effect, ran: &AtomicU32) -> Result<(), effect_gate::Refusal> {
    effect_gate::issue(e, &Timing::NONE, || { ran.fetch_add(1, Ordering::SeqCst); ((), true) })
}

/// A planner whose own class is `full` but whose data came from the agent is
/// held to the agent's slow envelope: a duty above the slow ceiling (30 %) is
/// refused with one `provenance-meet` record `[contributors, label, meet]`
/// and a receipt, the device is not touched and nothing is queued; the same
/// planner under the ceiling goes through; a task that never saw the agent is
/// not held to it.
#[test]
fn a_fully_rated_planner_is_held_to_the_brains_slow_envelope() {
    let _g = fresh();
    effect_gate::set_provenance_probe(probe);
    let base = azos_decision::total();
    let queued = logger_ring_len();
    let ran = AtomicU32::new(0);

    let Err(refusal) = run(&motor(PLANNER, Class::Reversible, 80), &ran) else {
        panic!("the planner's 80 % passed the slow envelope of the brain's data")
    };
    assert_eq!(refusal.why, Why::Provenance);
    assert_eq!(ran.load(Ordering::SeqCst), 0, "a refused effect reached the device");
    assert_eq!(logger_ring_len(), queued, "a refused effect left a record on the ring");
    let rec = azos_decision::lookup(refusal.receipt).expect("the receipt is a decision record");
    assert_eq!((rec.rule, rec.verdict, rec.subject), (Rule::ProvenanceMeet as u8, Verdict::Refuse as u8, PLANNER));
    assert_eq!(rec.n, [2, (SERVICE | AGENT) as u64, SLOW as u64], "two contributors, their label, the meet");

    // Exactly the ceiling goes; one above does not.
    run(&motor(PLANNER, Class::Reversible, 30), &ran).expect("30 % fits the slow envelope");
    assert!(run(&motor(PLANNER, Class::Reversible, 31), &ran).is_err());
    assert_eq!(ran.load(Ordering::SeqCst), 1);

    // The same duty from a task that never touched the agent's data.
    run(&motor(PLAIN, Class::Reversible, 80), &ran).expect("a service alone is `full`");
    assert_eq!(ran.load(Ordering::SeqCst), 2);

    let mut n = 0;
    azos_decision::for_each(|r| n += (r.seq > base && r.rule == Rule::ProvenanceMeet as u8) as u32);
    assert_eq!(n, 2, "one record per refusal, none for what went through");
}

/// The agent's own class envelope applies to the agent's own effects: the meet
/// of one contributor is its envelope.
#[test]
fn the_agent_alone_is_held_to_its_own_envelope() {
    let _g = fresh();
    effect_gate::set_provenance_probe(probe);
    let ran = AtomicU32::new(0);
    assert!(run(&motor(BRAIN, Class::Reversible, 80), &ran).is_err());
    run(&motor(BRAIN, Class::Reversible, 20), &ran).expect("20 % fits");
}

/// A stop is never refused by provenance, whatever the label and however hard
/// it brakes (`a1` is the strength): a task entitled to drive must always be
/// able to stop. **Canary.** Check provenance before the class match in
/// `issue`: the brake at 100 % is refused, red.
#[test]
fn a_stop_is_never_refused_by_provenance() {
    let _g = fresh();
    fn contained(tid: u32) -> (u32, u8) {
        if tid == 0xB4_0010 { (AGENT, 3) } else { probe(tid) }
    }
    effect_gate::set_provenance_probe(probe);
    let ran = AtomicU32::new(0);
    run(&motor(PLANNER, Class::Safe, 100), &ran).expect("a full brake under the slow envelope");
    effect_gate::set_provenance_probe(contained);
    run(&motor(0xB4_0010, Class::Safe, 100), &ran).expect("a full brake under containment");
    effect_gate::set_provenance_probe(probe);
    assert_eq!(ran.load(Ordering::SeqCst), 2);
}

/// An effect that carries no duty (a clock, a rail) has nothing to compare to
/// a ceiling: it passes at `slow` and is refused at `contained`.
#[test]
fn a_kind_without_a_duty_passes_slow_and_not_contained() {
    let _g = fresh();
    fn contained(tid: u32) -> (u32, u8) {
        if tid == 0xB4_0010 { (AGENT, 3) } else { probe(tid) }
    }
    effect_gate::set_provenance_probe(probe);
    let ran = AtomicU32::new(0);
    let clock = |tid| Effect { kind: KIND_CLOCK, class: Class::Reversible, subject: CLOCK, tid, a0: 7, a1: 1_000_000 };
    run(&clock(BRAIN), &ran).expect("slow has no ceiling for a clock");
    effect_gate::set_provenance_probe(contained);
    assert_eq!(run(&clock(0xB4_0010), &ran).err().map(|r| r.why), Some(Why::Provenance));
    // The motor at `contained` takes no duty at all; 0 is a coast, within the 0 ceiling.
    assert!(run(&motor(0xB4_0010, Class::Reversible, 1), &ran).is_err());
    run(&motor(0xB4_0010, Class::Reversible, 0), &ran).expect("a duty of 0 is within a ceiling of 0");
    effect_gate::set_provenance_probe(probe);
}

/// An empty label changes nothing: the gate is what it was before the probe.
#[test]
fn an_unlabelled_effect_is_not_held() {
    let _g = fresh();
    effect_gate::set_provenance_probe(probe);
    let ran = AtomicU32::new(0);
    run(&motor(0xB4_0099, Class::Reversible, 100), &ran).expect("no label, no meet");
}

/// The gate is generic and links no robot domain, so it keeps the duty ceiling
/// of each envelope level as numbers of its own; they are the degrade policy's
/// speed ceilings. Pinned here, not in `azos_behavior`, so the dependency
/// points from a test at both and not from a domain at the core.
///
/// **Canary.** Change one of `ENVELOPE_DUTY_CAP_PCT`: its level goes red.
#[test]
fn the_gates_duty_ceilings_are_the_degrade_policys_speed_ceilings() {
    use azos_degrade_policy::{
        DEGRADE_SPEED_CAP_CAUTIOUS_PCT, DEGRADE_SPEED_CAP_CONTAINED_PCT, DEGRADE_SPEED_CAP_FULL_PCT,
        DEGRADE_SPEED_CAP_SLOW_PCT,
    };
    let policy = [
        DEGRADE_SPEED_CAP_FULL_PCT,
        DEGRADE_SPEED_CAP_CAUTIOUS_PCT,
        DEGRADE_SPEED_CAP_SLOW_PCT,
        DEGRADE_SPEED_CAP_CONTAINED_PCT,
    ];
    for (level, (gate, want)) in effect_gate::ENVELOPE_DUTY_CAP_PCT.iter().zip(policy).enumerate() {
        assert_eq!(*gate as i32, want, "envelope level {level}");
    }
}

/// What the meet holds and what it does not. The provenance meet applies to
/// `Class::Reversible` effects that go through `effect_gate::issue`, and to
/// nothing else:
///
/// * `Class::Safe` (a stop, the way to a safe state) is outside it on purpose:
///   a task entitled to drive must always be able to stop, however
///   contained the data behind it is.
/// * An effect that does not go through the gate at all is not held by it.
///   Its holder is the capability and the topology's rows, not provenance.
///
/// The `match` has no wildcard, so a third class does not compile until
/// someone decides which side of the meet it is on. **Canary.** Check the meet
/// before the class match in `issue`: the `Safe` row is refused, red.
#[test]
fn only_the_reversible_class_is_in_the_meet() {
    let _g = fresh();
    fn contained(tid: u32) -> (u32, u8) {
        if tid == 0xB4_0020 { (AGENT, 3) } else { (0, 0) }
    }
    effect_gate::set_provenance_probe(contained);
    let ran = AtomicU32::new(0);
    for class in [Class::Safe, Class::Reversible] {
        let in_the_meet = match class {
            Class::Safe => false,
            Class::Reversible => true,
        };
        for kind in [KIND_MOTOR, KIND_CLOCK] {
            let e = Effect { kind, class, subject: if kind == KIND_MOTOR { WHEEL } else { CLOCK }, tid: 0xB4_0020, a0: 1, a1: 50 };
            let got = run(&e, &ran);
            if in_the_meet {
                assert_eq!(got.err().map(|r| r.why), Some(Why::Provenance), "{class:?} kind {kind}");
            } else {
                assert!(got.is_ok(), "{class:?} kind {kind} was held by provenance");
            }
        }
    }
    effect_gate::set_provenance_probe(probe);
}
