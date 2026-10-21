// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The behavior loop's call of the `Infer` interface
//! (`kernel/src/behavior_infer.rs`, pulled in with `#[path]`, so the code under
//! test is the code that ships), against a stand-in service that answers what
//! the real one can: a class, every refusal code, a reply of another model,
//! nothing written, logits that are not numbers.
//!
//! The property: **every way a call can end that is not a class is a missing
//! verdict, and a missing verdict is STOP** (`ml_link::mlp_result_for`). Canaries
//! (cargo features of this crate, known values in the kernel's):
//!
//! * `infer-refusal-canary`: a refused call passes as `Verdict(0)`, go forward.
//!   `a_refusal_is_never_a_class` and `every_missing_verdict_stops_the_robot`
//!   must go red.
//! * `infer-model-canary`: the model that answered is not compared with the one
//!   asked for. `a_reply_of_another_model_is_malformed` must go red.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use azos_abi::cap::CapPerms;
use azos_abi::error::Errno;
use azos_abi::ipc_msg::{CAP_MODE_DUP, CAP_MODE_MOVE};
use azos_devif::infer::{model_ref, Done, Tensor, HINT_NONE};
use azos_devif::{outcome, Cap, IdlError, IdlResult, Infer, InferIdl, MsgDesc, Out, Transport};

use super::behavior_infer::*;
use super::ml_link::{mlp_result_for, MlOutcome, CLASSES, CLASS_STOP};

const MODEL: u64 = 0xB51C_47D0_5181_16AC;
const DEADLINE_NS: u64 = 123_456_789;

/// The two tensor objects, as the helper sees them.
#[derive(Default)]
struct Mem {
    input: Option<[u32; 4]>,
    output: [u32; 3],
    refuse_prepare: bool,
    refuse_output: bool,
}

#[derive(Clone, Default)]
struct SharedMem(Rc<RefCell<Mem>>);

impl TensorMem for SharedMem {
    fn prepare(&mut self, input: [u32; 4]) -> bool {
        let mut m = self.0.borrow_mut();
        if m.refuse_prepare {
            return false;
        }
        m.input = Some(input);
        m.output = [POISON_BITS; 3];
        true
    }
    fn output(&mut self) -> Option<[u32; 3]> {
        let m = self.0.borrow();
        if m.refuse_output { None } else { Some(m.output) }
    }
}

/// What the stand-in service does with a call.
#[derive(Clone, Copy)]
enum Reply {
    /// Run: write these logits, answer `OK` with this `Done`.
    Run([f32; 3], Done),
    /// Run but write nothing.
    OkWritingNothing(Done),
    /// Answer this outcome code.
    Code(u32),
}

fn done() -> Done {
    Done { model_hash: MODEL, variant_id: 1, backend: 1, latency_us: 40, energy_uj: 20 }
}

struct Svc {
    mem: SharedMem,
    reply: Reply,
    calls: u32,
    last_model: u64,
    last_hint: u32,
}

impl Infer for Svc {
    fn infer(&mut self, model_ref: u64, _input: Cap<Tensor>, _output: Cap<Tensor>, energy_hint: u32) -> Out<Done> {
        self.calls += 1;
        self.last_model = model_ref;
        self.last_hint = energy_hint;
        match self.reply {
            Reply::Run(l, d) => {
                self.mem.0.borrow_mut().output = [l[0].to_bits(), l[1].to_bits(), l[2].to_bits()];
                Out::ok(d)
            }
            Reply::OkWritingNothing(d) => Out::ok(d),
            Reply::Code(c) => Out::err(c),
        }
    }
    fn attach(
        &mut self,
        _: Cap<azos_devif::infer::CmdQueue>,
        _: Cap<azos_devif::infer::DoneQueue>,
        _: Cap<azos_devif::infer::Arena>,
    ) -> Out<()> {
        Out::err(outcome::UNSUPPORTED)
    }
    fn detach(&mut self) -> Out<()> {
        Out::ok(())
    }
}

/// The kernel endpoint, replaced by a loopback into the stand-in service; it
/// keeps the request the service saw.
struct Loop<'a> {
    svc: &'a RefCell<Svc>,
    /// An error in place of the call, when set.
    fail: Option<IdlError>,
    seen: RefCell<MsgDesc>,
}

impl Transport for &Loop<'_> {
    fn call(&self, msg: &mut MsgDesc) -> IdlResult {
        *self.seen.borrow_mut() = *msg;
        if let Some(e) = self.fail {
            return Err(e);
        }
        let req = *msg;
        let _ = InferIdl::dispatch(&mut *self.svc.borrow_mut(), &req, msg);
        Ok(())
    }
}

struct Rig {
    mem: SharedMem,
    svc: RefCell<Svc>,
}

impl Rig {
    fn new(reply: Reply) -> Rig {
        let mem = SharedMem::default();
        Rig { svc: RefCell::new(Svc { mem: mem.clone(), reply, calls: 0, last_model: 0, last_hint: 99 }), mem }
    }

    fn call(&self, fail: Option<IdlError>, front: u16, right: u16) -> (Attempt, MsgDesc) {
        let l = Loop { svc: &self.svc, fail, seen: RefCell::new(MsgDesc::default()) };
        let mut mem = self.mem.clone();
        let a = infer_once(&l, &mut mem, Cap::<Tensor>::from_raw(7), Cap::<Tensor>::from_raw(8), MODEL, DEADLINE_NS, front, right);
        let seen = *l.seen.borrow();
        (a, seen)
    }
}

fn stop(o: MlOutcome) {
    let r = mlp_result_for(o);
    assert!(r.valid, "{o:?} must still decide");
    assert_eq!(r.class, CLASS_STOP, "{o:?} must decide STOP");
}

// ── the integer-only parts ───────────────────────────────────────────────

/// The kernel builds the input without a float: for every reading the bits are
/// the hardware division's (`n as f32 / 1000.0`, round to nearest even).
#[test]
fn the_input_is_the_float_division_for_every_reading() {
    for n in 0..=u16::MAX {
        assert_eq!(f32_bits_of_milli(n), (n as f32 / 1000.0).to_bits(), "n = {n}");
    }
    let w = input_words(800, 300);
    assert_eq!(w, [0.8f32.to_bits(), 0.3f32.to_bits(), 0.5f32.to_bits(), 0.9f32.to_bits()]);
}

/// The class from the logits' bits is the float argmax: the first of equal
/// values, +0.0 and -0.0 equal, negatives below positives.
#[test]
fn the_class_from_bits_is_the_float_argmax() {
    let vals = [-3.5f32, -0.25, -0.0, 0.0, 0.2, 0.45, 0.6, 1.0e-30, 7.0, 1.0e10];
    let float_argmax = |v: [f32; 3]| {
        let mut best = 0usize;
        for i in 1..3 {
            if v[i] > v[best] {
                best = i;
            }
        }
        best as u8
    };
    for &a in &vals {
        for &b in &vals {
            for &c in &vals {
                let bits = [a.to_bits(), b.to_bits(), c.to_bits()];
                assert_eq!(argmax3_bits(bits), Some(float_argmax([a, b, c])), "{a} {b} {c}");
            }
        }
    }
}

#[test]
fn logits_that_are_not_numbers_have_no_class() {
    for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, f32::from_bits(POISON_BITS)] {
        for at in 0..3 {
            let mut l = [0.1f32.to_bits(), 0.2f32.to_bits(), 0.3f32.to_bits()];
            l[at] = bad.to_bits();
            assert_eq!(argmax3_bits(l), None, "{bad} at {at}");
        }
    }
}

// ── one call ─────────────────────────────────────────────────────────────

/// A served call: the class, the model that ran, the input the service read,
/// and the request on the wire (model, hint, deadline, and both tensors lent
/// with the rights a tensor needs and nothing more).
#[test]
fn a_served_call_is_a_class_and_lends_its_tensors() {
    for (logits, class) in [([0.6, 0.0, 0.0], 0u8), ([0.2, 0.45, 0.0], 1), ([0.0, 0.0, 0.6], 2)] {
        let rig = Rig::new(Reply::Run(logits, done()));
        let (a, seen) = rig.call(None, 800, 300);
        assert_eq!(a.outcome, MlOutcome::Verdict(class));
        assert_eq!(a.why, Why::Served);
        assert_eq!(a.done, done(), "the reply's model, variant and backend travel with the verdict");
        assert_eq!(a.logits, [logits[0].to_bits(), logits[1].to_bits(), logits[2].to_bits()]);
        assert_eq!(rig.mem.0.borrow().input, Some(input_words(800, 300)));
        let s = rig.svc.borrow();
        assert_eq!((s.calls, s.last_model, s.last_hint), (1, MODEL, HINT_NONE));
        assert_eq!(seen.deadline, DEADLINE_NS, "the deadline is the descriptor's");
        assert_eq!(seen.n_caps, 2);
        assert_eq!((seen.caps[0].handle, seen.caps[1].handle), (7, 8), "input first");
        for c in &seen.caps[..2] {
            assert_eq!(c.mode, CAP_MODE_DUP, "lent, not moved: the loop keeps its objects");
            assert_ne!(c.mode, CAP_MODE_MOVE);
        }
        assert_eq!(seen.caps[0].rights, CapPerms::READ.union(CapPerms::MAP).bits() as u16, "the input is read");
        assert_eq!(seen.caps[1].rights, CapPerms::RW.union(CapPerms::MAP).bits() as u16, "the output is written");
    }
}

/// Every outcome code the service can answer instead of a run (and one it
/// does not know) is a missing verdict. The table: a refusal for want of time
/// is `Late`; no such model, not ready, busy, unsupported is `Unavailable`;
/// anything else is `Malformed`. **Canary `infer-refusal-canary`**: the code
/// passes as a class.
#[test]
fn a_refusal_is_never_a_class() {
    let table = [
        (outcome::DENIED, MlOutcome::Malformed),
        (outcome::BAD_ARGUMENT, MlOutcome::Malformed),
        (outcome::NOT_READY, MlOutcome::Unavailable),
        (outcome::FAULT, MlOutcome::Malformed),
        (outcome::UNSUPPORTED, MlOutcome::Unavailable),
        (outcome::BUSY, MlOutcome::Unavailable),
        (outcome::NO_RESOURCE, MlOutcome::Unavailable),
        (outcome::REFUSED, MlOutcome::Late),
        (outcome::NO_SERVER, MlOutcome::Unavailable),
        (10, MlOutcome::Malformed),
        (u32::MAX, MlOutcome::Malformed),
    ];
    for (code, want) in table {
        let rig = Rig::new(Reply::Code(code));
        let (a, _) = rig.call(None, 800, 300);
        assert_eq!(a.outcome, want, "code {code}");
        assert_eq!(a.why, Why::Code(code));
        assert!(!matches!(a.outcome, MlOutcome::Verdict(_)), "code {code} passed as a class");
        assert_eq!(a.logits, [0; 3], "a refusal carries no logits");
        assert_eq!(a.done, Done::default(), "and names no model");
    }
}

/// A call that returned an error instead of an answer. A deadline that had
/// passed is `Late`; nobody to call is `Unavailable`; a reply that was not the
/// interface's is `Malformed`.
#[test]
fn a_call_that_errors_is_a_missing_verdict() {
    let ed = Errno::EDEADLINE.to_syscall_ret() as isize;
    let table = [
        (IdlError::DeadlineExpired, MlOutcome::Late),
        (IdlError::Transport(ed), MlOutcome::Late),
        (IdlError::Transport(Errno::EBUSY.to_syscall_ret() as isize), MlOutcome::Unavailable),
        (IdlError::Transport(-1), MlOutcome::Unavailable),
        (IdlError::PeerDied, MlOutcome::Unavailable),
        (IdlError::NoConnection, MlOutcome::Unavailable),
        (IdlError::Refused, MlOutcome::Unavailable),
        (IdlError::BadInterface, MlOutcome::Malformed),
        (IdlError::BadOp, MlOutcome::Malformed),
        (IdlError::LevelTooNew, MlOutcome::Malformed),
        (IdlError::Malformed, MlOutcome::Malformed),
    ];
    for (e, want) in table {
        let rig = Rig::new(Reply::Run([0.6, 0.0, 0.0], done()));
        let (a, _) = rig.call(Some(e), 800, 300);
        assert_eq!(a.outcome, want, "{e:?}");
        assert_eq!(a.why, Why::Transport(e));
        assert_eq!(rig.svc.borrow().calls, 0, "the service never saw it");
    }
}

/// Every missing verdict, through the loop's own policy, holds STOP.
/// **Canary `infer-refusal-canary`.**
#[test]
fn every_missing_verdict_stops_the_robot() {
    let mut seen = Vec::new();
    for code in 1..=10u32 {
        seen.push(Rig::new(Reply::Code(code)).call(None, 800, 300).0.outcome);
    }
    for e in [IdlError::DeadlineExpired, IdlError::PeerDied, IdlError::Transport(-1), IdlError::Malformed] {
        seen.push(Rig::new(Reply::Code(0)).call(Some(e), 800, 300).0.outcome);
    }
    for o in seen {
        stop(o);
    }
    // A class out of the range is the same case.
    for c in CLASSES..=CLASSES + 3 {
        stop(MlOutcome::Verdict(c));
    }
}

/// `OK` from another model than the one asked for: the bundle was replaced
/// under the loop. **Canary `infer-model-canary`.**
#[test]
fn a_reply_of_another_model_is_malformed() {
    let other = Done { model_hash: MODEL ^ 1, ..done() };
    let rig = Rig::new(Reply::Run([0.6, 0.0, 0.0], other));
    let (a, _) = rig.call(None, 800, 300);
    assert_eq!(a.outcome, MlOutcome::Malformed);
    assert_eq!(a.why, Why::WrongModel(MODEL ^ 1));
    stop(a.outcome);
}

/// An `OK` that wrote nothing leaves the NaN the output was filled with: not a
/// class. (A zeroed output would have read as go forward.)
#[test]
fn an_ok_that_wrote_nothing_is_not_a_class() {
    let rig = Rig::new(Reply::OkWritingNothing(done()));
    let (a, _) = rig.call(None, 800, 300);
    assert_eq!((a.outcome, a.why), (MlOutcome::Malformed, Why::BadLogits));
}

#[test]
fn logits_that_are_not_numbers_are_malformed() {
    for bad in [f32::NAN, f32::INFINITY] {
        let rig = Rig::new(Reply::Run([0.6, bad, 0.0], done()));
        let (a, _) = rig.call(None, 800, 300);
        assert_eq!((a.outcome, a.why), (MlOutcome::Malformed, Why::BadLogits), "{bad}");
    }
}

/// Memory objects the loop cannot write are not called with; ones it cannot
/// read after the reply are malformed.
#[test]
fn memory_that_cannot_be_used_is_a_missing_verdict() {
    let rig = Rig::new(Reply::Run([0.6, 0.0, 0.0], done()));
    rig.mem.0.borrow_mut().refuse_prepare = true;
    let (a, _) = rig.call(None, 800, 300);
    assert_eq!((a.outcome, a.why), (MlOutcome::Unavailable, Why::Memory));
    assert_eq!(rig.svc.borrow().calls, 0, "no call is made on tensors that were not written");

    let rig = Rig::new(Reply::Run([0.6, 0.0, 0.0], done()));
    rig.mem.0.borrow_mut().refuse_output = true;
    let (a, _) = rig.call(None, 800, 300);
    assert_eq!((a.outcome, a.why), (MlOutcome::Malformed, Why::Memory));
}

/// The adapter changes nothing but the mode and rights of the entries it lent,
/// and only the MOVE ones.
#[test]
fn lending_rewrites_only_the_move_entries() {
    struct Echo(Cell<Option<MsgDesc>>);
    impl Transport for &Echo {
        fn call(&self, msg: &mut MsgDesc) -> IdlResult {
            self.0.set(Some(*msg));
            Ok(())
        }
    }
    let echo = Echo(Cell::new(None));
    let mut m = MsgDesc::default();
    m.n_caps = 3;
    m.words[0] = 0xAB;
    m.caps[0].mode = CAP_MODE_MOVE;
    m.caps[1].mode = CAP_MODE_MOVE;
    m.caps[2].mode = CAP_MODE_DUP;
    m.caps[2].rights = 0x5;
    Lending(&echo).call(&mut m).unwrap();
    let got = echo.0.get().unwrap();
    assert_eq!((got.caps[0].mode, got.caps[1].mode, got.caps[2].mode), (CAP_MODE_DUP, CAP_MODE_DUP, CAP_MODE_DUP));
    assert_eq!(got.caps[2].rights, 0x5, "an entry that was already a copy is left as it was");
    assert_eq!(got.words[0], 0xAB);
}

/// The reference the kernel pins is the one the library derives from a digest.
#[test]
fn the_model_reference_is_the_first_eight_bytes_of_the_digest() {
    let mut d = [0u8; 32];
    d[..8].copy_from_slice(&MODEL.to_le_bytes());
    assert_eq!(model_ref(&d), MODEL);
}
