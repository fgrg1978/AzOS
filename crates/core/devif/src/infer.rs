// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Infer` interface: run a model on whatever backend the machine has.
//!
//! The inference service (INFSRV, a ring-3 task) serves it from an endpoint:
//! **one client context is one endpoint capability**, its badge the context.
//! The client names a model by [`model_ref`] (the first eight bytes of the
//! digest of the model's signed `.MBL` manifest, `azos_ml::bundle`), hands it
//! tensors in memory objects and is told which variant of the bundle ran, on
//! which backend, and what the run cost. The service, not the client, picks the
//! variant: it walks the bundle's signed fallback list and takes the first
//! whose backend is present, whose working memory fits and whose signed
//! worst-case time fits the time left to the caller's deadline
//! (`azos_ml::bundle::Manifest::select`).
//!
//! # Two ways in, one cost
//!
//! * [`Infer::infer`] is the call: both tensors are memory objects moved with
//!   the request, the reply is the [`Done`]. For a one-off run, or a client
//!   that is happy to make a fresh pair per run.
//! * [`Infer::attach`] is the context of an accelerator, the shape a GPU
//!   reuses: the client makes a **command queue**, a **completion queue** and
//!   an **arena**, moves the three with `attach` and keeps the other ends. The
//!   intended protocol is that a run is then no call: the client writes the
//!   tensors into the arena, pushes a [`Cmd`] on the command queue and sleeps
//!   on the completion queue's futex doorbell; the service pops the command,
//!   runs it and pushes a [`Completion`]. Both queues are meant to be
//!   `SpscSlots<SLOT_WORDS>` of `azos_rings::region` over their memory object,
//!   so that the only calls are the ones that change authority (`attach`,
//!   `detach`) and the sleep. This module defines the message and slot layouts
//!   only; no service drives the queues yet and no test exercises them.
//!
//! The deadline and its clock travel in the message descriptor of the call
//! (`MsgDesc::deadline`, `MsgDesc::clock_id`; the server reads the caller's
//! value) and in the command ([`Cmd::deadline`], [`Cmd::clock_id`]), never as
//! an argument: the field the whole IPC layer honours, which the client stub
//! sets with `with_deadline` (absolute, on the monotonic clock). 0 is no
//! deadline.
//!
//! What a run costs is in the answer: [`Done::latency_us`] and
//! [`Done::energy_uj`]. Charging them to the caller's scheduling context is
//! intended future work and needs a charge mechanism that does not exist yet;
//! today they are reported to the client and nothing else.
//!
//! # Outcomes
//!
//! `NO_RESOURCE`: the service holds no model with that `model_ref`.
//! `BAD_ARGUMENT`: a tensor is not the size the model's manifest says, an
//! arena offset is outside the arena or misaligned, an `energy_hint` is not
//! one of [`HINT_NONE`], [`HINT_LOW_ENERGY`]. `UNSUPPORTED`: no variant of the
//! bundle runs on a backend this machine has. `BUSY`: every variant that has a
//! backend needs more working memory than is free now. `REFUSED`: no variant's
//! signed worst-case time fits the deadline, so nothing ran (a model that
//! cannot make the deadline is told so at once and the caller degrades, rather
//! than learning it late). `FAULT`: the backend failed the run. `NOT_READY`:
//! the model is registered but its variant is not loaded yet.

use crate::outcome::Out;
use azos_idl::{azos_interface, Cap, Reader, Wire, Writer};

/// The interface id (ASCII "INFR").
pub const INFER_ID: u32 = 0x494E_4652;

/// What a `Cap<Tensor>` names: a memory object holding one tensor, laid out as
/// the model's manifest says. The input is held with `READ`, the output with
/// `READ | WRITE`.
pub struct Tensor;
/// What a `Cap<CmdQueue>` names: a memory object holding a ring of [`Cmd`]
/// slots, the client its producer.
pub struct CmdQueue;
/// What a `Cap<DoneQueue>` names: a memory object holding a ring of
/// [`Completion`] slots, the service its producer.
pub struct DoneQueue;
/// What a `Cap<Arena>` names: the memory object a context's commands name
/// tensors in, by offset (`READ | WRITE` for the service).
pub struct Arena;

/// [`Infer::infer`]'s and [`Cmd`]'s `energy_hint`: the publisher's order of
/// the fallback list decides.
pub const HINT_NONE: u32 = 0;
/// ... among the variants that fit, the one whose signed energy is lowest
/// (a tie goes to the earlier in the list).
pub const HINT_LOW_ENERGY: u32 = 1;

/// Words of one slot of either queue: one 64-byte cache line.
pub const SLOT_WORDS: usize = 8;
/// Alignment of a tensor offset in an arena, bytes.
pub const TENSOR_ALIGN: u64 = 16;

/// The reference a client names a model by: the first eight bytes of the
/// SHA-256 digest of the model's manifest, little-endian. The service answers
/// the same value as [`Done::model_hash`], so a client that was served after
/// the model was replaced sees that it was.
pub fn model_ref(manifest_digest: &[u8; 32]) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&manifest_digest[..8]);
    u64::from_le_bytes(w)
}

/// What one run was: the answer of [`Infer::infer`] and the body of a
/// [`Completion`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Done {
    /// [`model_ref`] of the bundle that ran.
    pub model_hash: u64,
    /// The `variant_id` of the bundle's variant that ran.
    pub variant_id: u32,
    /// The backend it ran on (`azos_ml::bundle::BACKEND_*`).
    pub backend: u32,
    /// Wall time of the run, microseconds (saturating).
    pub latency_us: u32,
    /// Energy the run was charged, microjoules: the signed cost table's figure
    /// for the variant (saturating).
    pub energy_uj: u32,
}

impl Wire for Done {
    const WORDS: usize = 5;
    const CAPS: usize = 0;
    fn put(&self, w: &mut Writer<'_>) {
        self.model_hash.put(w);
        self.variant_id.put(w);
        self.backend.put(w);
        self.latency_us.put(w);
        self.energy_uj.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        let model_hash = u64::get(r);
        let variant_id = u32::get(r);
        let backend = u32::get(r);
        let latency_us = u32::get(r);
        Done { model_hash, variant_id, backend, latency_us, energy_uj: u32::get(r) }
    }
}

/// One slot of the command queue: run `model_ref` on the tensors at `in_off`
/// and `out_off` of the context's arena. The tensors' sizes are the model's,
/// not the command's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cmd {
    /// The client's name for the command, echoed in the completion.
    pub tag: u64,
    pub model_ref: u64,
    /// Where the input tensor starts in the arena, a multiple of
    /// [`TENSOR_ALIGN`].
    pub in_off: u64,
    /// Where the output tensor goes, a multiple of [`TENSOR_ALIGN`]; the two
    /// ranges do not overlap.
    pub out_off: u64,
    /// [`HINT_NONE`] or [`HINT_LOW_ENERGY`].
    pub energy_hint: u32,
    /// Absolute deadline, nanoseconds on `clock_id`; 0 = none.
    pub deadline: u64,
    /// The clock `deadline` is read on (`ClockId` raw value; 0 = `MONO`).
    pub clock_id: u32,
}

/// One slot of the completion queue: how the command `tag` ended. `code` is an
/// outcome ([`crate::outcome`]) and `done` is meaningful only when it is `OK`
/// (zero otherwise).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub tag: u64,
    pub code: u32,
    pub done: Done,
}

impl Cmd {
    /// The queue slot of the command: the fields in order, the last word zero.
    pub fn to_slot(&self) -> [u64; SLOT_WORDS] {
        [
            self.tag,
            self.model_ref,
            self.in_off,
            self.out_off,
            self.energy_hint as u64,
            self.deadline,
            self.clock_id as u64,
            0,
        ]
    }

    /// The command in a slot. `None` when a field does not fit its type or the
    /// reserved word is not zero: a slot the service does not understand is
    /// refused, not guessed at.
    pub fn from_slot(s: &[u64; SLOT_WORDS]) -> Option<Cmd> {
        if s[7] != 0 {
            return None;
        }
        Some(Cmd {
            tag: s[0],
            model_ref: s[1],
            in_off: s[2],
            out_off: s[3],
            energy_hint: u32::try_from(s[4]).ok()?,
            deadline: s[5],
            clock_id: u32::try_from(s[6]).ok()?,
        })
    }

    /// Whether the tensors fit the arena: both offsets aligned to
    /// [`TENSOR_ALIGN`], `in_bytes` at `in_off` and `out_bytes` at `out_off`
    /// inside `arena_bytes`, the two ranges disjoint, and the hint one this
    /// interface defines. `Err` is the outcome code (`BAD_ARGUMENT`); the
    /// service checks before it touches the arena, so a hostile offset reaches
    /// no byte outside it.
    pub fn check(&self, arena_bytes: u64, in_bytes: u64, out_bytes: u64) -> Result<(), u32> {
        use crate::outcome::BAD_ARGUMENT;
        if self.energy_hint > HINT_LOW_ENERGY || self.in_off % TENSOR_ALIGN != 0 || self.out_off % TENSOR_ALIGN != 0 {
            return Err(BAD_ARGUMENT);
        }
        let range = |off: u64, len: u64| off.checked_add(len).filter(|&end| end <= arena_bytes).map(|end| (off, end));
        let (Some((ia, ib)), Some((oa, ob))) = (range(self.in_off, in_bytes), range(self.out_off, out_bytes)) else {
            return Err(BAD_ARGUMENT);
        };
        // Empty tensors overlap nothing; a model with none is refused by the
        // manifest check, not here.
        if ia < ob && oa < ib {
            return Err(BAD_ARGUMENT);
        }
        Ok(())
    }
}

impl Completion {
    /// The queue slot of the completion: the fields in order, the last word
    /// zero.
    pub fn to_slot(&self) -> [u64; SLOT_WORDS] {
        [
            self.tag,
            self.code as u64,
            self.done.model_hash,
            self.done.variant_id as u64,
            self.done.backend as u64,
            self.done.latency_us as u64,
            self.done.energy_uj as u64,
            0,
        ]
    }

    /// The completion in a slot; `None` for a field that does not fit its type
    /// or a reserved word that is not zero.
    pub fn from_slot(s: &[u64; SLOT_WORDS]) -> Option<Completion> {
        if s[7] != 0 {
            return None;
        }
        Some(Completion {
            tag: s[0],
            code: u32::try_from(s[1]).ok()?,
            done: Done {
                model_hash: s[2],
                variant_id: u32::try_from(s[3]).ok()?,
                backend: u32::try_from(s[4]).ok()?,
                latency_us: u32::try_from(s[5]).ok()?,
                energy_uj: u32::try_from(s[6]).ok()?,
            },
        })
    }
}

#[azos_interface(id = 0x494E_4652, level = 1)]
pub trait Infer {
    /// Run the model `model_ref` on `input` and write the result to `output`,
    /// before the caller's deadline (`MsgDesc::deadline`). Both memory objects
    /// are moved with the request and are the model's sizes exactly
    /// (`BAD_ARGUMENT` otherwise). The answer says which variant ran, where and
    /// at what cost. A run is not idempotent in what it charges, so a lost reply
    /// is not asked again: the caller degrades (`on_failure(degrade)`). Needs
    /// `WRITE`.
    #[at_most_once]
    #[on_failure(degrade)]
    #[deadline_ns = 50_000_000]
    #[budget_us = 500]
    fn infer(&mut self, model_ref: u64, input: Cap<Tensor>, output: Cap<Tensor>, energy_hint: u32) -> Out<Done>;
    /// Start the context's queued traffic: the service pops [`Cmd`]s from
    /// `cmds`, runs them on tensors in `arena` and pushes a [`Completion`] on
    /// `done` for each. `BUSY` while a context is attached, `BAD_ARGUMENT` for
    /// a handle that is not a memory object of the right rights, `NOT_READY`
    /// when the service has no backend yet. Needs `WRITE`.
    #[once_only]
    #[on_failure(degrade)]
    #[deadline_ns = 5_000_000]
    #[budget_us = 200]
    fn attach(&mut self, cmds: Cap<CmdQueue>, done: Cap<DoneQueue>, arena: Cap<Arena>) -> Out<()>;
    /// Stop the context's traffic and let go of the three objects; a command
    /// not yet popped completes with `REFUSED` first. Needs `WRITE`.
    #[idempotent]
    fn detach(&mut self) -> Out<()>;
}
