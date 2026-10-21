// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The behavior loop as a client of the `Infer` interface: the part with no
//! kernel in it.
//!
//! `behavior_ml.rs` owns the tasks, the memory objects and the waiting; this
//! file is what one call is. It takes a transport (the kernel endpoint caller
//! in the kernel, a loopback to a stand-in server in `tests/host/behavior-tests`,
//! which includes this file) and the two tensor memory objects, and answers the
//! [`MlOutcome`] `azos_behavior::ml_link` turns into the loop's verdict. Every
//! way a call can end that is not a class is a missing verdict, and a missing
//! verdict is STOP (`ml_link`'s doc says why); the mapping from the ways to the
//! outcomes is [`outcome_of_code`] and [`outcome_of_error`], and nothing else
//! decides.
//!
//! # No floating point
//!
//! The model takes four `f32` and answers three. The loop's readings are `u16`
//! millimetres, and the kernel keeps off floating point (soft-float on aarch64,
//! no F on riscv64imac), so the input is built from the readings with integer
//! arithmetic ([`f32_bits_of_milli`], correctly rounded, equal to
//! `n as f32 / 1000.0` for every `n`) and the class is the argmax of the
//! logits' bit patterns ([`argmax3_bits`], equal to the float comparison).
//!
//! # The tensors are lent, not moved
//!
//! `Infer::infer` takes its two tensors as `Cap<Tensor>`, which move: the
//! caller would lose the object the answer is written in. [`Lending`] turns
//! the two entries of the request into copies the kernel makes
//! (`CAP_MODE_DUP`, with the rights a tensor needs and no more), so the loop
//! keeps its two objects for the life of the boot and reads the output from
//! its own end after the reply.

use azos_abi::cap::CapPerms;
use azos_abi::error::Errno;
use azos_abi::ipc_msg::{CAP_MODE_DUP, CAP_MODE_MOVE};
use azos_behavior::ml_link::{MlOutcome, CLASSES};
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
    /// The client is not up: no helper task, no tensor objects, no capability
    /// on the endpoint.
    NotReady,
    /// The previous call has not come back yet; no second one is made.
    Pending,
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
    // Canary `infer-refusal-canary` (host suite only, never in a kernel): a
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
