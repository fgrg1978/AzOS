// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What one endpoint serves: the `Infer` interface, the receipts, and the
//! lease of the verdict log.
//!
//! The endpoint is the one `endpoint.infer` names. Three interfaces come in
//! through it and are told apart by the id in the request's header:
//!
//! * `Infer` ([`azos_devif::infer`]): [`Service::infer`] is the call. The
//!   broker admits first ([`crate::broker`]), so a call that cannot make its
//!   deadline is refused before a tensor is mapped; only an admitted call maps
//!   its two memory objects, runs the variant and settles the cost.
//!   `attach`/`detach` are the accelerator form of the same interface (a
//!   command queue, a completion queue and an arena): this service has no
//!   queue to drive yet, and says `UNSUPPORTED` rather than pretend.
//! * `Decisions` ([`azos_decisions`]): the broker's journal, so the receipt in
//!   a verdict is read back with the client everybody reads decisions with. A
//!   caller reads the records of its own badge and no others; a call with no
//!   badge reads none.
//! * [`InferLog`]: lends the memory object of the caller's own verdict log
//!   ([`crate::verdict`]), read and map only. Every context has an object of
//!   its own, so the lease shows nothing of another context.
//!
//! The service touches nothing but a [`Platform`]: a clock, two tensors
//! mapped for the length of a call, the capability of the verdict log, and the
//! memory the blobs are in.
//!
//! # The blob arena is memory the system may take back
//!
//! The blobs are weights read from signed files on the volume: the service can
//! make them again. Its arena is a volatile memory object
//! (`SHM_ATTR_VOLATILE`, [`Platform::blobs_resume`]), marked droppable
//! between calls and held while one runs. A call that finds it purged
//! ([`Blobs::Lost`]) forgets the models, takes new storage, loads the bundles
//! again ([`Platform::blobs_rebuild`], verifying every signature and digest as
//! at start-up) and goes on; the time that took is out of the caller's
//! deadline, because it passes before the admission reads the clock. The
//! contexts' energy accounts and the receipts are the broker's and are not
//! touched.
//!
//! The system takes a droppable arena back only when it as a whole is short of
//! frames. A Domain that is over its own mark is told on its pressure port
//! instead ([`Platform::pressure_rose`]), and the arena is the service's to
//! give: at the end of the call that finds the level risen it is let go
//! ([`Platform::blobs_park`]), and the next call rebuilds it. A rise is
//! reported once, so the arena is rebuilt once and kept until the level rises
//! again, not given back by every call that runs while the level stays up. The
//! port is read where a call ends, not while the service waits, so an idle
//! service gives memory back at its next call.

use crate::broker::{Broker, Request};
use crate::exec::Exec;
use crate::load::Arena;
use crate::verdict::{Publisher, Verdict};
use azos_abi::cap::CapPerms;
use azos_decisions::{DecisionsIdl, Service as DecisionsService, DECISIONS_ID};
use azos_devif::infer::{Done, Infer, InferIdl, Tensor, HINT_LOW_ENERGY};
use azos_devif::outcome::{self, Out};
use azos_idl::{azos_interface, header_id, Cap, Lent, MsgDesc, Reader, Wire, Writer};

/// Why the tensors could not be had.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TensorError {
    /// A capability that is not a memory object, or is stale, or lacks the
    /// right to map it.
    Unmappable,
    /// The output object is read-only.
    ReadOnly,
}

/// What a call finds in the blob arena when it is about to read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blobs {
    /// The blobs are as the loader left them.
    Kept,
    /// The memory was taken back (or never came): the arena has to be made
    /// again before any blob is read.
    Lost,
}

/// What the service needs from the machine.
pub trait Platform {
    /// The monotonic clock, nanoseconds.
    fn now_ns(&self) -> u64;

    /// Map the memory objects `input` and `output` (capabilities the caller
    /// moved here), call `f` with their bytes and a reader of the clock, and
    /// give both back (unmapped and closed), whatever `f` did. The slices are
    /// the whole regions, a multiple of the page size; the output is writable.
    fn with_tensors(
        &mut self,
        input: u32,
        output: u32,
        f: &mut dyn FnMut(&[u8], &mut [u8], &dyn Fn() -> u64),
    ) -> Result<(), TensorError>;

    /// Give back a memory object the caller moved here and the call does not
    /// use.
    fn drop_cap(&mut self, cap: u32);

    /// The memory object of context `slot`'s verdict log, made on the first
    /// ask (a context that never asks for its log takes no object: the
    /// system-wide table is small, and eight made at start filled it). `None`
    /// when it cannot be made.
    fn log_region(&mut self, slot: usize) -> Option<LogObject>;

    /// A call is about to read the blob arena: it may not be taken back until
    /// [`Platform::blobs_park`]. Says whether the blobs survived the time it
    /// was droppable.
    fn blobs_resume(&mut self) -> Blobs;

    /// Has the Domain's memory pressure risen (to warning, or from warning to
    /// critical) since this was last asked? Each rise is reported once; a
    /// platform with no source of pressure never says so.
    fn pressure_rose(&mut self) -> bool;

    /// The call is over: the blob arena may be taken back until the next one.
    /// `give_back`: give it back now (the object is let go, so the next
    /// [`Platform::blobs_resume`] answers [`Blobs::Lost`]).
    fn blobs_park(&mut self, give_back: bool);

    /// Take new storage for the arena (`arena.reset`) and load the bundles
    /// into it again, adding their models to `broker`. A platform that cannot
    /// get storage leaves the arena empty, and the broker with no model.
    fn blobs_rebuild(&mut self, broker: &mut Broker, arena: &mut Arena<'_>);
}

// ── the log lease ────────────────────────────────────────────────────────

/// What a `Lent<LogRegion>` names: the memory object of a context's verdict log
/// ([`crate::verdict`]), lent read-only.
pub struct LogRegion;

/// The interface id (ASCII "IFLG").
pub const LOG_ID: u32 = 0x4946_4C47;

/// [`InferLog::log`]'s answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogLease {
    /// Bytes of the object.
    pub bytes: u32,
    /// The object, lent with `READ` and `MAP`.
    pub region: Lent<LogRegion>,
}

impl Default for LogLease {
    fn default() -> Self {
        LogLease { bytes: 0, region: Lent::none() }
    }
}

impl Wire for LogLease {
    const WORDS: usize = 1 + <Lent<LogRegion> as Wire>::WORDS;
    const CAPS: usize = <Lent<LogRegion> as Wire>::CAPS;
    fn put(&self, w: &mut Writer<'_>) {
        self.bytes.put(w);
        self.region.put(w);
    }
    fn get(r: &mut Reader<'_>) -> Self {
        LogLease { bytes: u32::get(r), region: <Lent<LogRegion> as Wire>::get(r) }
    }
}

#[azos_interface(id = 0x4946_4C47, level = 1)]
pub trait InferLog {
    /// The verdict log of the caller's context: lend its memory object (read
    /// and map only). The object is the context's own and holds no other
    /// context's verdicts. The caller maps it and reads it with
    /// `LogReader::latest` for as long as it runs, with no further call.
    /// `NO_RESOURCE` for a call that came through no badged capability, `BUSY`
    /// when every context slot belongs to another badge, `NOT_READY` when the
    /// service could not make the context's object (made on this first call;
    /// until then the context's verdicts are published nowhere).
    #[idempotent]
    fn log(&mut self) -> Out<LogLease>;
}

/// A context's verdict log object: its capability and size, and, the one
/// time it was just made, its mapping for the publisher.
#[derive(Clone, Copy)]
pub struct LogObject {
    pub cap: u32,
    pub bytes: u32,
    /// The mapping of an object made by this ask: `bytes` long, aligned to
    /// `verdict::region_align`, writable, mapped for the life of the program,
    /// and referred to by nothing else yet. `None` on every later ask.
    pub fresh: Option<*mut u8>,
}

// ── the service ──────────────────────────────────────────────────────────

/// The call being served.
#[derive(Clone, Copy, Default)]
struct Caller {
    badge: Option<u32>,
    /// Absolute, on `clock`; 0 = none.
    deadline_ns: u64,
    clock: u32,
}

pub struct Service<'a, P: Platform> {
    pub broker: Broker,
    pub arena: Arena<'a>,
    pub exec: Exec,
    pub plat: P,
    pub publisher: Option<Publisher>,
    caller: Caller,
}

impl<'a, P: Platform> Service<'a, P> {
    pub fn new(broker: Broker, arena: Arena<'a>, exec: Exec, plat: P, publisher: Option<Publisher>) -> Self {
        Service { broker, arena, exec, plat, publisher, caller: Caller::default() }
    }

    /// Serve the request in `req`, writing the answer into `rep`.
    pub fn handle(&mut self, req: &MsgDesc, rep: &mut MsgDesc) {
        self.caller = Caller {
            badge: (req.flags & azos_abi::ipc_msg::MSG_BADGED != 0).then_some(req.badge as u32),
            deadline_ns: req.deadline,
            clock: req.clock_id,
        };
        let id = if req.n_words > 0 { header_id(req.words[0]) } else { 0 };
        // Every dispatcher answers a request of another interface with
        // `BadInterface`, so an id none of them knows gets that from the last.
        let _ = match id {
            DECISIONS_ID => DecisionsIdl::dispatch(&mut DecisionsService(self.broker.journal.view(self.caller.badge)), req, rep),
            LOG_ID => InferLogIdl::dispatch(self, req, rep),
            _ => InferIdl::dispatch(self, req, rep),
        };
    }

    fn publish(&mut self, ctx: Option<usize>, v: Verdict) {
        if let (Some(slot), Some(p)) = (ctx, self.publisher.as_mut()) {
            let _ = p.publish(slot, v);
        }
    }

    /// Refuse a call that reached no run: close what it moved, tell the
    /// context's log, answer.
    fn refused(&mut self, caps: [u32; 2], ctx: Option<usize>, v: Verdict) -> Out<Done> {
        for c in caps {
            self.plat.drop_cap(c);
        }
        self.publish(ctx, v);
        Out::err(v.code)
    }
}

/// What the closure that runs the variant found.
enum Ran {
    /// A region is smaller than the model's tensor.
    TooSmall,
    /// The backend answered or failed; how long it took, nanoseconds.
    Done(bool, u64),
}

impl<P: Platform> Service<'_, P> {
    /// Hold the blob arena for a call: if its memory was taken back, make it
    /// again. Models whose blobs were in the old storage are forgotten first,
    /// so no span outlives it.
    fn resume_blobs(&mut self) {
        if self.plat.blobs_resume() == Blobs::Lost {
            self.arena.reset(&mut []);
            self.broker.forget_models();
            self.plat.blobs_rebuild(&mut self.broker, &mut self.arena);
        }
    }

    /// One `Infer::infer`, without the arena's bracket (see the trait impl).
    fn run_call(&mut self, model_ref: u64, input: Cap<Tensor>, output: Cap<Tensor>, energy_hint: u32) -> Out<Done> {
        let caps = [input.raw(), output.raw()];
        let now = self.plat.now_ns();
        let mut v = Verdict { model_ref, at_ns: now, ..Verdict::default() };
        let Some(badge) = self.caller.badge else {
            v.code = outcome::NO_RESOURCE;
            return self.refused(caps, None, v);
        };
        // Only the monotonic clock is served (the kernel refuses another before
        // it gets here), and a hint is one the interface defines.
        if energy_hint > HINT_LOW_ENERGY || self.caller.clock != 0 {
            v.code = outcome::BAD_ARGUMENT;
            return self.refused(caps, None, v);
        }
        // A call that will be admitted needs the blobs. Getting them back is
        // time the caller's deadline pays for, so the clock is read after.
        self.resume_blobs();
        let now = self.plat.now_ns();
        let budget_us = match self.caller.deadline_ns {
            0 => None,
            d => Some((d.saturating_sub(now) / 1000).min(u32::MAX as u64) as u32),
        };
        let req = Request { badge, model_ref, low_energy: energy_hint == HINT_LOW_ENERGY, budget_us, now_ns: now };
        let adm = match self.broker.admit(&req) {
            Ok(a) => a,
            Err(None) => {
                v.code = outcome::NO_RESOURCE;
                return self.refused(caps, None, v);
            }
            Err(Some(r)) => {
                v.code = r.code;
                v.reason = r.reason;
                v.receipt = r.receipt;
                (v.backend, v.variant_id) = r.candidate.unwrap_or_default();
                return self.refused(caps, r.ctx, v);
            }
        };
        v.variant_id = adm.slot.v.id;
        v.backend = adm.slot.v.backend;
        v.receipt = adm.receipt;
        let Some(span) = adm.slot.span else {
            // Admission only hands out variants that have a blob.
            self.broker.settle(&adm, false, 0);
            v.code = outcome::FAULT;
            return self.refused(caps, Some(adm.ctx), v);
        };

        // The model's tensor sizes, and the blob: both outlive the closure.
        let (in_b, out_b) = match self.broker.find(model_ref) {
            Some((_, m)) => (m.in_bytes as usize, m.out_bytes as usize),
            None => (0, 0),
        };
        let blob = self.arena.bytes(span);
        let exec = self.exec;
        let mut ran = Ran::TooSmall;
        let mapped = self.plat.with_tensors(caps[0], caps[1], &mut |inp, outp, clock| {
            if inp.len() < in_b || outp.len() < out_b {
                return;
            }
            let t0 = clock();
            let ok = exec.run(blob, &inp[..in_b], &mut outp[..out_b]);
            ran = Ran::Done(ok, clock().saturating_sub(t0));
        });
        let (ok, elapsed) = match (&mapped, &ran) {
            (Ok(()), Ran::Done(ok, ns)) => (*ok, *ns),
            _ => (false, 0),
        };
        let s = self.broker.settle(&adm, ok, elapsed);
        v.latency_us = s.latency_us;
        v.energy_uj = s.energy_uj;
        v.overrun_us = s.overrun_us;
        v.at_ns = self.plat.now_ns();
        v.code = match (mapped, ran) {
            (Ok(()), Ran::Done(true, _)) => outcome::OK,
            (Ok(()), Ran::Done(false, _)) => outcome::FAULT,
            _ => outcome::BAD_ARGUMENT,
        };
        self.publish(Some(adm.ctx), v);
        if v.code != outcome::OK {
            return Out::err(v.code);
        }
        Out::ok(Done {
            model_hash: model_ref,
            variant_id: v.variant_id,
            backend: v.backend,
            latency_us: v.latency_us,
            energy_uj: v.energy_uj,
        })
    }
}

impl<P: Platform> Infer for Service<'_, P> {
    /// The call, bracketed by the arena: whatever its outcome, the arena is
    /// droppable again when it returns.
    fn infer(&mut self, model_ref: u64, input: Cap<Tensor>, output: Cap<Tensor>, energy_hint: u32) -> Out<Done> {
        let out = self.run_call(model_ref, input, output, energy_hint);
        // The Domain is short of memory: the blobs are what the service can
        // make again, so they go now and the next call pays for them.
        let give_back = self.plat.pressure_rose();
        if give_back {
            self.arena.reset(&mut []);
            self.broker.forget_models();
        }
        self.plat.blobs_park(give_back);
        out
    }

    fn attach(
        &mut self,
        cmds: Cap<azos_devif::infer::CmdQueue>,
        done: Cap<azos_devif::infer::DoneQueue>,
        arena: Cap<azos_devif::infer::Arena>,
    ) -> Out<()> {
        for c in [cmds.raw(), done.raw(), arena.raw()] {
            self.plat.drop_cap(c);
        }
        Out::err(outcome::UNSUPPORTED)
    }

    fn detach(&mut self) -> Out<()> {
        // Nothing can be attached, so there is nothing to stop.
        Out::ok(())
    }
}

impl<P: Platform> InferLog for Service<'_, P> {
    fn log(&mut self) -> Out<LogLease> {
        let Some(badge) = self.caller.badge else { return Out::err(outcome::NO_RESOURCE) };
        let Some(slot) = self.broker.context(badge) else { return Out::err(outcome::BUSY) };
        let Some(r) = self.plat.log_region(slot) else { return Out::err(outcome::NOT_READY) };
        if let (Some(base), Some(p)) = (r.fresh, self.publisher.as_mut()) {
            // SAFETY: `LogObject::fresh`'s contract is `Publisher::add`'s: a
            // writable mapping of `bytes`, aligned, for the life of the program,
            // that nothing else refers to.
            let _ = unsafe { p.add(slot, base, r.bytes as usize) };
        }
        let rights = CapPerms::READ.union(CapPerms::MAP).bits() as u16;
        Out::ok(LogLease { bytes: r.bytes, region: Lent::dup(r.cap, rights) })
    }
}
