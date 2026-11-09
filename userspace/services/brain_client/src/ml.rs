// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The behaviour engine as a client of the `Infer` interface: the part with no
//! system call in it, which the host suite includes by path.
//!
//! The engine asks the inference service (`MLSRV.ELF`, `endpoint.infer`) for a
//! class once per cycle and waits for it for a bounded time. Every way a call
//! can end that is not a class is a missing verdict, and L1 holds a stop on a
//! missing verdict (`behave::Ml::Missing`): the engine never drives on a
//! verdict it did not get. The mapping from the ways a call ends to
//! [`MlOutcome`] is [`outcome_of_code`], [`outcome_of_error`] and
//! [`Caller`]'s timeout, and nothing else decides.
//!
//! # No floating point
//!
//! The model takes four `f32` and answers three. The readings are `u16`
//! millimetres and this program is built without floating point, so the input
//! is built with integer arithmetic ([`f32_bits_of_milli`], correctly rounded,
//! equal to `n as f32 / 1000.0` for every `n`) and the class is the argmax of
//! the logits' bit patterns ([`argmax3_bits`], equal to the float comparison).
//!
//! # The tensors are lent, not moved
//!
//! `Infer::infer` takes its two tensors as `Cap<Tensor>`, which move: the
//! caller would lose the object the answer is written in. [`Lending`] turns the
//! two entries of the request into copies the kernel makes (`CAP_MODE_DUP`,
//! with the rights a tensor needs and no more), so the engine keeps its two
//! objects for its life and reads the output from its own end after the reply.

/// The model the engine runs: the first eight bytes of the SHA-256 of the
/// manifest of `/fat/BEHAVIOR.MBL` (`azos_devif::infer::model_ref`),
/// little-endian. The build checks it (`tools/image/make_mbl.py
/// --expect-ref-from`, `mk/images.mk`), so a bundle built from other weights,
/// another cost table or another name fails the build until this line says
/// what it is.
pub const BEHAVIOR_MODEL_REF: u64 = 0xb51c47d0518116ac;

/// The endpoint the service serves the `Infer` interface on: the name behind
/// the topology target `endpoint.infer`.
pub const INFER_ENDPOINT: &[u8] = b"infer";

/// The `MLP`'s classes (`azos_ml::CLASS_NAMES`).
pub const CLASS_GO: u8 = 0;
pub const CLASS_TURN: u8 = 1;
pub const CLASS_STOP: u8 = 2;
/// Number of classes; anything at or above is malformed.
pub const CLASSES: u8 = 3;

/// How one cycle's request ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MlOutcome {
    /// The service answered with this class.
    Verdict(u8),
    /// No reply within the budget, or the service refused the call because its
    /// signed worst case does not fit the deadline.
    Late,
    /// The call did not reach a server that could run the model: nobody serves
    /// the endpoint, or it holds no such model (an unsigned bundle is not
    /// loaded), is not ready, or is busy.
    Unavailable,
    /// It answered, but not with a class (a failed run, a reply of another
    /// model, logits that are not numbers, a class out of range).
    Malformed,
}

impl MlOutcome {
    /// The outcome as one word, for the helper thread to hand across.
    pub const fn to_word(self) -> u32 {
        match self {
            MlOutcome::Verdict(c) => c as u32,
            MlOutcome::Late => 0x100,
            MlOutcome::Unavailable => 0x101,
            MlOutcome::Malformed => 0x102,
        }
    }

    /// [`MlOutcome::to_word`]'s inverse; a word that is none of them is
    /// `Malformed`.
    pub const fn from_word(w: u32) -> MlOutcome {
        match w {
            0..=0xFF => MlOutcome::Verdict(w as u8),
            0x100 => MlOutcome::Late,
            0x101 => MlOutcome::Unavailable,
            _ => MlOutcome::Malformed,
        }
    }
}

/// The verdict L1 acts on for `outcome`.
pub fn verdict_of(outcome: MlOutcome) -> crate::behave::Ml {
    use crate::behave::Ml;
    match outcome {
        MlOutcome::Verdict(CLASS_GO) => Ml::Go,
        MlOutcome::Verdict(CLASS_TURN) => Ml::Turn,
        MlOutcome::Verdict(CLASS_STOP) => Ml::Stop,
        MlOutcome::Verdict(_) | MlOutcome::Late | MlOutcome::Unavailable | MlOutcome::Malformed => Ml::Missing,
    }
}

use azos_abi::cap::CapPerms;
use azos_abi::error::Errno;
use azos_abi::ipc_msg::{CAP_MODE_DUP, CAP_MODE_MOVE};
use azos_devif::infer::{Done, Tensor, HINT_NONE};
use azos_devif::{outcome, Cap, IdlError, IdlResult, InferCall, InferClient, MsgDesc, Out, Transport};

/// Bytes of the output tensor: the three logits as `f32`. (The input is
/// [`input_words`]: four of them, 16 bytes, which is what the bundle's manifest
/// says.)
pub const OUTPUT_BYTES: usize = 12;

/// `0.5f32`.
const HALF_BITS: u32 = 0x3F00_0000;
/// `0.9f32`.
const NINE_TENTHS_BITS: u32 = 0x3F66_6666;
/// A quiet NaN: what the output is filled with before a call, so an `OK` that
/// wrote nothing reads as malformed and never as a class.
pub const POISON_BITS: u32 = 0x7FC0_0000;

/// What the server may do with the input: read it and map it.
const INPUT_RIGHTS: u16 = CapPerms::READ.union(CapPerms::MAP).bits() as u16;
/// What the server may do with the output: read, write and map it.
const OUTPUT_RIGHTS: u16 = CapPerms::RW.union(CapPerms::MAP).bits() as u16;

/// The bit pattern of `n as f32 / 1000.0`, by integer arithmetic only,
/// rounded to nearest even as the hardware division does.
pub fn f32_bits_of_milli(n: u16) -> u32 {
    if n == 0 {
        return 0;
    }
    let num = n as u64;
    // The exponent e with 2^e <= n / 1000 < 2^(e + 1): n is 1..=65535, so the
    // value is 0.001..65.535 and e is -10..=6.
    let mut e: i32 = -10;
    while e < 6 {
        let next = e + 1;
        let (lhs, rhs) = if next < 0 { (num << (-next), 1000u64) } else { (num, 1000u64 << next) };
        if lhs >= rhs {
            e = next;
        } else {
            break;
        }
    }
    // The 24-bit significand: round(n * 2^(23 - e) / 1000).
    let shift = (23 - e) as u32;
    let scaled = num << shift;
    let mut q = scaled / 1000;
    let r = scaled % 1000;
    if 2 * r > 1000 || (2 * r == 1000 && q & 1 == 1) {
        q += 1;
    }
    if q == 1 << 24 {
        q >>= 1;
        e += 1;
    }
    (((e + 127) as u32) << 23) | (q as u32 & 0x007F_FFFF)
}

/// The input tensor for the two range readings, as `f32` bit patterns.
pub fn input_words(front_mm: u16, right_mm: u16) -> [u32; 4] {
    [f32_bits_of_milli(front_mm), f32_bits_of_milli(right_mm), HALF_BITS, NINE_TENTHS_BITS]
}

/// The class of the largest of three logits given as `f32` bit patterns: the
/// first of equal ones, as the float comparison `v[i] > v[best]` takes it. `None` when a logit is
/// not a finite number (NaN, an infinity): the model did not answer.
pub fn argmax3_bits(l: [u32; 3]) -> Option<u8> {
    // Sign-magnitude to an order-preserving key; -0.0 is +0.0, as in `>`.
    let key = |b: u32| -> Option<u32> {
        if (b >> 23) & 0xFF == 0xFF {
            return None;
        }
        let b = if b == 0x8000_0000 { 0 } else { b };
        Some(if b >> 31 == 1 { !b } else { b | 0x8000_0000 })
    };
    let k = [key(l[0])?, key(l[1])?, key(l[2])?];
    let mut best = 0usize;
    for i in 1..3 {
        if k[i] > k[best] {
            best = i;
        }
    }
    Some(best as u8)
}

/// The transport that lends the request's capabilities instead of moving them
/// (see the module doc): entry 0 is the input, entry 1 the output.
pub struct Lending<T>(pub T);

impl<T: Transport> Transport for Lending<T> {
    fn call(&self, msg: &mut MsgDesc) -> IdlResult {
        let n = (msg.n_caps as usize).min(msg.caps.len());
        for (i, c) in msg.caps[..n].iter_mut().enumerate() {
            if c.mode == CAP_MODE_MOVE {
                c.mode = CAP_MODE_DUP;
                c.rights = if i == 0 { INPUT_RIGHTS } else { OUTPUT_RIGHTS };
            }
        }
        self.0.call(msg)
    }
}

/// The loop's two tensor memory objects, as the code that owns them lets this
/// file touch them.
pub trait TensorMem {
    /// Write the input and poison the output. `false`: the objects cannot be
    /// written (the call is not made).
    fn prepare(&mut self, input: [u32; 4]) -> bool;
    /// The three logits the server wrote. `None`: the output cannot be read.
    fn output(&mut self) -> Option<[u32; 3]>;
}

/// Why a call ended as it did, for the loop's one-shot line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// A class came back.
    Served,
    /// The service answered with this outcome code (`azos_devif::outcome`).
    Code(u32),
    /// The call did not reach a server, or no answer came back.
    Transport(IdlError),
    /// The memory objects could not be written or read.
    Memory,
    /// `OK`, but the output holds no finite logits.
    BadLogits,
    /// `OK`, but another model than the one asked for answered
    /// (the reply's `model_hash`).
    WrongModel(u64),
}

/// One call, finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub outcome: MlOutcome,
    pub why: Why,
    /// What the service says ran: meaningful for a verdict, zero otherwise.
    pub done: Done,
    /// The logits' bit patterns: meaningful for a verdict, zero otherwise.
    pub logits: [u32; 3],
}

impl Attempt {
    /// A call that produced no class: `outcome` is what the loop is told.
    pub const fn missing(outcome: MlOutcome, why: Why) -> Attempt {
        Attempt { outcome, why, done: Done { model_hash: 0, variant_id: 0, backend: 0, latency_us: 0, energy_uj: 0 }, logits: [0; 3] }
    }
}

/// The outcome of a service that answered with `code` instead of a run.
///
/// `REFUSED` is the broker saying no variant's signed worst case fits the
/// deadline: the call came too late to be worth running, so it is `Late`. A
/// service that holds no such model, is not ready, is busy or has no backend
/// is `Unavailable`. Anything else (a tensor of the wrong size, a failed run,
/// a capability it would not take, a code this client does not know) is a
/// service that answered and did not make sense: `Malformed`.
pub fn outcome_of_code(code: u32) -> MlOutcome {
    // Canary `infer-refusal-canary` (host suite only, never enabled by a build): a
    // refusal passes as a class. The suite must catch it.
    if cfg!(feature = "infer-refusal-canary") {
        return MlOutcome::Verdict(0);
    }
    match code {
        outcome::REFUSED => MlOutcome::Late,
        outcome::NO_RESOURCE | outcome::NOT_READY | outcome::BUSY | outcome::UNSUPPORTED | outcome::NO_SERVER => {
            MlOutcome::Unavailable
        }
        _ => MlOutcome::Malformed,
    }
}

/// The outcome of a call that returned an error instead of an answer.
///
/// A deadline that had passed (before the call was queued, or on the server's
/// side) is `Late`. A call that never reached a server (no capability, nobody
/// serving, the server died, a node that is gone, refused to cross) is
/// `Unavailable`. A reply that was not the interface's is `Malformed`.
pub fn outcome_of_error(e: IdlError) -> MlOutcome {
    match e {
        IdlError::DeadlineExpired => MlOutcome::Late,
        IdlError::Transport(code) if code as i64 == Errno::EDEADLINE.to_syscall_ret() => MlOutcome::Late,
        IdlError::Transport(_) | IdlError::PeerDied | IdlError::NoConnection | IdlError::Refused => {
            MlOutcome::Unavailable
        }
        IdlError::BadInterface | IdlError::BadOp | IdlError::LevelTooNew | IdlError::Malformed => MlOutcome::Malformed,
    }
}

/// One `Infer::infer` of the model `model_ref` on the readings, through
/// `transport`, before the absolute `deadline_ns` (monotonic clock; the
/// service reads it from the message and refuses a call it cannot make in
/// time). `input` and `output` are the loop's two tensor objects.
pub fn infer_once<T: Transport, M: TensorMem>(
    transport: T,
    mem: &mut M,
    input: Cap<Tensor>,
    output: Cap<Tensor>,
    model_ref: u64,
    deadline_ns: u64,
    front_mm: u16,
    right_mm: u16,
) -> Attempt {
    if !mem.prepare(input_words(front_mm, right_mm)) {
        return Attempt::missing(MlOutcome::Unavailable, Why::Memory);
    }
    let mut client = InferClient::new(Lending(transport)).with_deadline(deadline_ns);
    let Out { code, value: done } = match client.infer(model_ref, input, output, HINT_NONE) {
        Ok(out) => out,
        Err(e) => return Attempt::missing(outcome_of_error(e), Why::Transport(e)),
    };
    if code != outcome::OK {
        return Attempt::missing(outcome_of_code(code), Why::Code(code));
    }
    // A reply from another model than the one asked for: the bundle was
    // replaced under the loop. Canary `infer-model-canary` (host suite only)
    // skips the check.
    if done.model_hash != model_ref && !cfg!(feature = "infer-model-canary") {
        return Attempt::missing(MlOutcome::Malformed, Why::WrongModel(done.model_hash));
    }
    let Some(logits) = mem.output() else {
        return Attempt::missing(MlOutcome::Malformed, Why::Memory);
    };
    match argmax3_bits(logits) {
        Some(class) if class < CLASSES => Attempt { outcome: MlOutcome::Verdict(class), why: Why::Served, done, logits },
        _ => Attempt::missing(MlOutcome::Malformed, Why::BadLogits),
    }
}

/// The call and its wait, which only the ring-3 helper can do: the service may
/// never answer, and a blocked call has no timeout of its own.
pub trait Caller {
    /// An earlier call has not come back: no second one is made behind it.
    fn busy(&self) -> bool;
    /// Make the call on the two readings and wait for it at most `budget_ns`;
    /// `None` when no reply came in that time.
    fn call(&mut self, front_mm: u16, right_mm: u16, budget_ns: u64) -> Option<MlOutcome>;
}

/// This cycle's verdict request. A call still out, or one that does not come
/// back within the budget, is `Late`: a missing verdict.
pub fn cycle(c: &mut impl Caller, front_mm: u16, right_mm: u16, budget_ns: u64) -> MlOutcome {
    if c.busy() {
        return MlOutcome::Late;
    }
    match c.call(front_mm, right_mm, budget_ns) {
        Some(o) => o,
        // Canary `ml-timeout-canary` (host suite only, never enabled by a
        // build): a call that timed out passes as a class.
        None if cfg!(feature = "ml-timeout-canary") => MlOutcome::Verdict(CLASS_GO),
        None => MlOutcome::Late,
    }
}
