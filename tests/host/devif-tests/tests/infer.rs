// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Infer` interface: its op table, its wire form, the deadline riding the
//! message descriptor, and the command and completion slots of an attached
//! context.

use azos_devif::infer::{
    self, model_ref, Arena, Cmd, CmdQueue, Completion, Done, DoneQueue, Tensor, HINT_LOW_ENERGY, HINT_NONE, SLOT_WORDS,
    TENSOR_ALIGN,
};
use azos_devif::{outcome, Infer, InferCall, InferClient, InferIdl, Out, INFER_ID};
use azos_idl::{header, Cap, MsgDesc, Result as IdlResult, Transport};
use std::cell::{Cell, RefCell};

/// A service that records what it was handed and answers a fixed model.
struct Svc {
    known: u64,
    ctx: Option<(Cap<CmdQueue>, Cap<DoneQueue>, Cap<Arena>)>,
    last: Option<(u64, Cap<Tensor>, Cap<Tensor>, u32)>,
}

impl Svc {
    fn new(known: u64) -> Self {
        Svc { known, ctx: None, last: None }
    }
}

const RAN: Done = Done { model_hash: 0xAAAA_BBBB_CCCC_DDDD, variant_id: 7, backend: 2, latency_us: 1_250, energy_uj: 4_000 };

impl Infer for Svc {
    fn infer(&mut self, model_ref: u64, input: Cap<Tensor>, output: Cap<Tensor>, energy_hint: u32) -> Out<Done> {
        self.last = Some((model_ref, input, output, energy_hint));
        if model_ref != self.known {
            return Out::err(outcome::NO_RESOURCE);
        }
        if energy_hint > HINT_LOW_ENERGY {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        Out::ok(RAN)
    }
    fn attach(&mut self, cmds: Cap<CmdQueue>, done: Cap<DoneQueue>, arena: Cap<Arena>) -> Out<()> {
        if self.ctx.is_some() {
            return Out::err(outcome::BUSY);
        }
        self.ctx = Some((cmds, done, arena));
        Out::ok(())
    }
    fn detach(&mut self) -> Out<()> {
        self.ctx = None;
        Out::ok(())
    }
}

struct Loop<'a> {
    server: &'a RefCell<Svc>,
    sent: Cell<u32>,
    last: RefCell<MsgDesc>,
}

impl Transport for &Loop<'_> {
    fn call(&self, msg: &mut MsgDesc) -> IdlResult {
        self.sent.set(self.sent.get() + 1);
        let req = *msg;
        *self.last.borrow_mut() = req;
        let _ = InferIdl::dispatch(&mut *self.server.borrow_mut(), &req, msg);
        Ok(())
    }
}

fn lp(server: &RefCell<Svc>) -> Loop<'_> {
    Loop { server, sent: Cell::new(0), last: RefCell::new(MsgDesc::default()) }
}

/// The table is the trait in order; `infer` is the one op that is not
/// idempotent (it charges), a lost reply is not asked again, and each shape
/// fits the message: `infer` is three words and two capabilities with a
/// seven-word reply, `attach` is three capabilities.
///
/// **Canary.** Make `infer` `#[idempotent]`, or add a fourth capability to
/// `attach`: red.
#[test]
fn the_op_table_is_the_trait_and_infer_is_not_retried() {
    let names: Vec<&str> = InferIdl::OPS.iter().map(|o| o.name).collect();
    assert_eq!(names, ["infer", "attach", "detach"]);
    assert_eq!(InferIdl::ID, INFER_ID);
    let [i, a, d] = [InferIdl::OPS[0], InferIdl::OPS[1], InferIdl::OPS[2]];
    assert!(i.at_most_once() && !i.idempotent() && !i.retry_safe(), "deduplicated by the transport, never re-run");
    assert_eq!((i.req_words, i.req_caps, i.rep_words, i.rep_caps), (3, 2, 7, 0));
    assert_eq!((a.req_words, a.req_caps, a.rep_words), (1, 3, 2));
    assert!(d.idempotent());
    assert!(i.deadline_ns > 0 && i.budget_us > 0, "an inference declares its contract");
    assert_eq!(i.on_failure, Some(azos_idl::OnFailure::Degrade));
}

/// The request is the header, the model and the hint, and the two tensors are
/// the capability entries in order; the reply carries the whole `Done`; the
/// caller's deadline rides the descriptor.
///
/// **Canary.** Swap `input` and `output` in the stub: the order assertion is
/// red.
#[test]
fn infer_moves_two_tensors_and_answers_what_ran() {
    let svc = RefCell::new(Svc::new(0x1234));
    let l = lp(&svc);
    let mut c = InferClient::new(&l).with_deadline(9_000_000);
    let (inp, outp) = (Cap::<Tensor>::from_raw(5), Cap::<Tensor>::from_raw(6));
    assert_eq!(c.infer(0x1234, inp, outp, HINT_LOW_ENERGY), Ok(Out::ok(RAN)));
    let r = *l.last.borrow();
    assert_eq!((r.n_words, r.n_caps), (3, 2));
    assert_eq!(r.words[0], header(INFER_ID, 1, InferIdl::OP_INFER));
    assert_eq!((r.words[1], r.words[2]), (0x1234, HINT_LOW_ENERGY as u64));
    assert_eq!((r.caps[0].handle, r.caps[1].handle), (5, 6), "input first");
    assert_eq!(r.deadline, 9_000_000, "the deadline is the descriptor's, not an argument");
    assert_eq!(svc.borrow().last, Some((0x1234, inp, outp, HINT_LOW_ENERGY)));

    assert_eq!(c.infer(0x9999, inp, outp, HINT_NONE).unwrap().code, outcome::NO_RESOURCE);
    assert_eq!(c.infer(0x1234, inp, outp, 2).unwrap().code, outcome::BAD_ARGUMENT);
}

/// A context is three capability entries, once; a second attach is `BUSY` and
/// changes nothing; detaching twice is served.
///
/// **Canary.** Let `attach` replace an attached context: the `BUSY` row is red.
#[test]
fn a_context_attaches_three_objects_once() {
    let svc = RefCell::new(Svc::new(1));
    let l = lp(&svc);
    let mut c = InferClient::new(&l);
    let (q, d, a) = (Cap::<CmdQueue>::from_raw(10), Cap::<DoneQueue>::from_raw(11), Cap::<Arena>::from_raw(12));
    assert_eq!(c.attach(q, d, a), Ok(Out::ok(())));
    let r = *l.last.borrow();
    assert_eq!((r.n_words, r.n_caps), (1, 3));
    assert_eq!((r.caps[0].handle, r.caps[1].handle, r.caps[2].handle), (10, 11, 12));
    assert_eq!(svc.borrow().ctx, Some((q, d, a)));
    assert_eq!(c.attach(Cap::from_raw(20), Cap::from_raw(21), Cap::from_raw(22)).unwrap().code, outcome::BUSY);
    assert_eq!(svc.borrow().ctx, Some((q, d, a)), "the refused context did not replace the attached one");
    assert_eq!(c.detach(), Ok(Out::ok(())));
    assert_eq!(c.detach(), Ok(Out::ok(())));
    assert_eq!(svc.borrow().ctx, None);
}

fn cmd() -> Cmd {
    Cmd {
        tag: 0xFEED,
        model_ref: 0x1234,
        in_off: 0,
        out_off: 64,
        energy_hint: HINT_LOW_ENERGY,
        deadline: 5_000_000,
        clock_id: 0,
    }
}

/// A command and a completion are one slot each and come back as they went;
/// the reserved word and a field too wide for its type are refused, not
/// guessed at.
///
/// **Canary.** Make `from_slot` ignore the reserved word, or drop the
/// `u32::try_from` on the hint: the matching row is red.
#[test]
fn slots_round_trip_and_refuse_what_they_do_not_understand() {
    assert_eq!(SLOT_WORDS * 8, 64, "one cache line");
    let c = cmd();
    assert_eq!(Cmd::from_slot(&c.to_slot()), Some(c));
    let mut s = c.to_slot();
    s[7] = 1;
    assert_eq!(Cmd::from_slot(&s), None, "reserved word");
    let mut s = c.to_slot();
    s[4] = 1 << 32;
    assert_eq!(Cmd::from_slot(&s), None, "hint wider than u32");
    let mut s = c.to_slot();
    s[6] = 1 << 32;
    assert_eq!(Cmd::from_slot(&s), None, "clock wider than u32");

    let done = Completion { tag: 0xFEED, code: outcome::OK, done: RAN };
    assert_eq!(Completion::from_slot(&done.to_slot()), Some(done));
    let refused = Completion { tag: 3, code: outcome::REFUSED, done: Done::default() };
    assert_eq!(Completion::from_slot(&refused.to_slot()), Some(refused));
    let mut s = done.to_slot();
    s[7] = 9;
    assert_eq!(Completion::from_slot(&s), None);
    let mut s = done.to_slot();
    s[5] = u64::from(u32::MAX) + 1;
    assert_eq!(Completion::from_slot(&s), None, "latency wider than u32");
}

/// The arena check: tensors inside, aligned, disjoint, with a known hint; a
/// hostile offset that wraps is refused.
///
/// **Canary.** Replace `checked_add` with `+`: the wrap row panics (overflow
/// checks are on); drop the overlap test: the overlap rows are red.
#[test]
fn a_command_names_tensors_inside_the_arena_and_nowhere_else() {
    let (arena, inb, outb) = (256u64, 64u64, 32u64);
    let ok = cmd();
    assert_eq!(ok.check(arena, inb, outb), Ok(()));
    let bad = |f: &dyn Fn(&mut Cmd)| {
        let mut c = cmd();
        f(&mut c);
        c.check(arena, inb, outb)
    };
    assert_eq!(bad(&|c| c.in_off = 8), Err(outcome::BAD_ARGUMENT), "misaligned input");
    assert_eq!(bad(&|c| c.out_off = 72), Err(outcome::BAD_ARGUMENT), "misaligned output");
    assert_eq!(bad(&|c| c.out_off = 240), Err(outcome::BAD_ARGUMENT), "output runs past the arena");
    assert_eq!(bad(&|c| c.in_off = 224), Err(outcome::BAD_ARGUMENT), "input runs past the arena");
    assert_eq!(bad(&|c| c.out_off = 32), Err(outcome::BAD_ARGUMENT), "output overlaps input");
    assert_eq!(bad(&|c| { c.in_off = 64; c.out_off = 0 }), Ok(()), "adjacent, out below in");
    assert_eq!(bad(&|c| { c.in_off = 16; c.out_off = 0 }), Err(outcome::BAD_ARGUMENT), "input overlaps output from above");
    assert_eq!(bad(&|c| c.in_off = u64::MAX - (TENSOR_ALIGN - 1)), Err(outcome::BAD_ARGUMENT), "an offset that wraps");
    assert_eq!(bad(&|c| c.energy_hint = 2), Err(outcome::BAD_ARGUMENT), "a hint nobody defined");
    assert_eq!(ok.check(arena, inb, outb), Ok(()));
    assert_eq!(infer::HINT_NONE, 0);
}

/// A model is named by the first eight bytes of its manifest digest, little
/// endian: the same bytes read as the same number on every ISA.
///
/// **Canary.** Read the bytes big-endian: red.
#[test]
fn the_model_ref_is_the_digest_prefix_little_endian() {
    let mut d = [0u8; 32];
    for (i, b) in d.iter_mut().enumerate() {
        *b = i as u8 + 1;
    }
    assert_eq!(model_ref(&d), 0x0807_0605_0403_0201);
    d[8] = 0xFF;
    assert_eq!(model_ref(&d), 0x0807_0605_0403_0201, "bytes past the eighth do not count");
}
