// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The behavior loop's side of the ring-3 inference service.
//!
//! The loop's MLP runs in `userspace/services/infsrv` (`MLSRV.ELF`), which the
//! loop starts itself and then reaches through the `Infer` interface
//! (`azos_devif::infer`) on `endpoint.infer`, the way any client does: one call
//! per cycle naming the model ([`BEHAVIOR_MODEL_REF`], the signed bundle
//! `/fat/BEHAVIOR.MBL`), the two range readings in an input tensor, the three
//! logits in an output tensor, and a deadline of [`ML_REPLY_TIMEOUT_US`]. What a
//! missing answer turns into is `azos_behavior::ml_link`'s policy, not this
//! file's: every way a call can end that is not a class is STOP.
//!
//! What one call is, is `behavior_infer.rs` (no kernel in it, tested on the
//! host). This file is the kernel around it.
//!
//! # Why a task of its own makes the call
//!
//! The kernel's endpoint call (`azos_syscall::kcall`) blocks until the server
//! answers: the deadline it carries is checked before the call is queued and
//! read by the server, and nothing ends the wait of a caller whose server is
//! alive and not answering. The behavior loop cannot be that caller: a service
//! that hangs would hang the loop that arbitrates, publishes the motor command
//! and feeds the brain link. So the `ml-infer` task makes the calls, one at a
//! time, and the loop waits for it with a timer
//! (`azos_driver_server::reply_wait::wait_for_reply`, the wait the
//! user-driver proxy uses). A call that does not come back in time is `Late`,
//! and so is every cycle until it does (`Why::Pending`): at most one call is
//! ever out. The helper runs at the loop's priority, which is what the call
//! donates to the service while it is served.
//!
//! The helper owns what the calls need: the loop's capability on the endpoint
//! (badged, so the broker accounts the loop as one context) and its two tensor
//! memory objects, lent to the service on every call (`behavior_infer::Lending`).

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

use azos_abi::cap::CapPerms;
use azos_behavior::ml_link::{MlAbsence, MlLinkStats, MlOutcome};
use azos_behavior::types::MlpResult;
use azos_devif::infer::Tensor;
use azos_devif::Cap;
use azos_driver_server::reply_wait::{wait_for_reply, ReplyWaitEnv, WaitOutcome};
use azos_drv_sys::kprintln;
use azos_ipc::memobj::{memobj_create_cap, memobj_with_span_ref, MemPerms, MemSpec};
use azos_robot::ModelRecord;
use azos_sched::{BlockOutcome, WaitReason};
use azos_sync::SpinLock;
use azos_syscall::kcall::{self, KernelEndpoint};

use crate::behavior_infer::{self, Attempt, TensorMem, Why, OUTPUT_BYTES, POISON_BITS};

/// The service image on the FAT32 volume.
const MLSRV_PATH: &[u8] = b"/fat/MLSRV.ELF";

/// The endpoint the service serves the `Infer` interface on: the name behind
/// the topology target `endpoint.infer` (the target's `endpoint.` prefix is
/// the kind, `azos_ipc::cap_seed`).
const INFER_ENDPOINT: &[u8] = b"infer";

/// The badge of the loop's capability on [`INFER_ENDPOINT`]: the context the
/// broker admits, accounts and answers the loop as. Stamped by the kernel; no
/// topology row holds a capability with it.
const BEHAVIOR_BADGE: u32 = 1;

/// The model the loop runs: the first eight bytes of the SHA-256 of the
/// manifest of `/fat/BEHAVIOR.MBL` (`azos_devif::infer::model_ref`), little-endian.
/// The build checks it (`tools/make_mbl.py --expect-ref-from`, `mk/images.mk`), so
/// a bundle built from other weights, another cost table or another name fails
/// the build until this line says what it is.
pub const BEHAVIOR_MODEL_REF: u64 = 0xb51c47d0518116ac;

/// How long one cycle waits for the service's verdict.
///
/// 10 % of the loop's 100 ms period. The service's own work is a few thousand
/// instructions and the round trip a few thousand more (`[BSTEP]` measures
/// both), so a reply that has not come after 10 ms is a service that is not
/// running, not one that is slow; waiting longer only eats into the period
/// the rest of the loop (the brain link, arbitration, the motor publish)
/// needs. The same figure is the deadline the call carries, so the broker
/// refuses at once a call it could not finish in time.
///
/// Wave 11: Kconfig `ML_REPLY_TIMEOUT_US` (Robot menu, default 10000).
pub const ML_REPLY_TIMEOUT_US: u64 = azos_limits::ML_REPLY_TIMEOUT_US;

/// TID of the service the loop started; 0 = not started on this boot.
static ML_SERVICE_TID: AtomicU32 = AtomicU32::new(0);

// ── The helper task's state ──────────────────────────────────────────────

/// `HELPER`: no helper task was made on this boot.
const HELPER_NONE: u8 = 0;
/// `HELPER`: made, setting up.
const HELPER_STARTING: u8 = 1;
/// `HELPER`: serving requests.
const HELPER_READY: u8 = 2;
/// `HELPER`: it could not set up (no memory object): no call is made, and
/// every cycle says so.
const HELPER_FAILED: u8 = 3;
static HELPER: AtomicU8 = AtomicU8::new(HELPER_NONE);
static HELPER_TID: AtomicU32 = AtomicU32::new(0);

/// The request: written by the loop (the only writer), then `REQUEST` is
/// bumped to publish it. The helper answers by writing `RESULT` and then
/// `DONE`, both to the request's number.
static REQUEST: AtomicU32 = AtomicU32::new(0);
static DONE: AtomicU32 = AtomicU32::new(0);
/// `front_mm | right_mm << 16`.
static REQ_READINGS: AtomicU32 = AtomicU32::new(0);
/// The call's absolute deadline, nanoseconds on the monotonic clock.
static REQ_DEADLINE_NS: AtomicU64 = AtomicU64::new(0);
/// Who waits for the answer and until when (`Timer(deadline)` ticks), so the
/// helper can wake exactly that wait.
static WAITER_TID: AtomicU32 = AtomicU32::new(0);
static WAITER_DEADLINE: AtomicU64 = AtomicU64::new(0);
/// The answer to request `.0`.
static RESULT: SpinLock<Option<(u32, Attempt)>> = SpinLock::new(None);

/// The helper parks on this and the loop wakes it with the same value.
const PARK: u64 = u64::MAX;

/// Start the ML service and the task that calls it. Called once, by the
/// behavior task, before its loop.
///
/// Refused, like autorun, while the actuation gate is not installed (Q1.4:
/// no ring-3 program starts before it). A boot that cannot start it gets no
/// ML verdicts (`MlOutcome::NotLaunched`) and L1 holds STOP for as long as
/// ML is enabled (owner decision 2026-09-28, fail closed); it says so once,
/// here.
pub fn launch() {
    if !azos_robot::motor::motor_gate_installed() {
        azos_drv_sys::kwarn!("[ML] ring-3 ML service NOT started: the actuation gate is not installed");
        return;
    }
    if azos_behavior::safety::safe_mode_active() {
        azos_drv_sys::kwarn!("[ML] ring-3 ML service NOT started: safe mode");
        return;
    }
    // Supervised (wave 11): a service that dies is restarted from the same
    // image under the supervisor's policy, and L1 holds STOP for every cycle
    // without a verdict meanwhile (`ml_link`), so a restart lets nothing
    // through before the new service answers.
    let rc = crate::drv_supervisor::spawn_supervised(MLSRV_PATH);
    if rc > 0 {
        ML_SERVICE_TID.store(rc as u32, Ordering::Release);
        kprintln!("[ML] ring-3 ML service /fat/MLSRV.ELF started, tid={} (reply budget {} us)",
            rc, ML_REPLY_TIMEOUT_US);
        HELPER.store(HELPER_STARTING, Ordering::Release);
        // Pinned beside the loop (hart 2, `main.rs`): it runs while the loop
        // sleeps on the timer, and wakes it.
        azos_sched::task_create_affinity("ml-infer", infer_task, 0, azos_sched::BEHAVIOR_PRIORITY, 2);
    } else {
        azos_drv_sys::kwarn!("[ML] ring-3 ML service NOT started (spawn /fat/MLSRV.ELF rc={}): no ML \
                   verdicts this boot, L1 holds STOP (ml_enabled=0 turns ML off)", rc);
    }
}

/// The service's TID, 0 when it was never started. After a restart, the
/// successor's (the supervisor's entry for `MLSRV_PATH`); while a successor
/// is due, the one that died.
pub fn service_tid() -> u32 {
    let launched = ML_SERVICE_TID.load(Ordering::Acquire);
    if launched == 0 {
        return 0;
    }
    match crate::drv_supervisor::current_tid(MLSRV_PATH) {
        Some(tid) if tid != 0 => tid,
        _ => launched,
    }
}

// ── The helper ───────────────────────────────────────────────────────────

/// The two tensor memory objects, as the helper reads and writes them:
/// the table references (the kernel's own end), not the capabilities.
struct Mem {
    input: u32,
    output: u32,
}

/// Store `words` at the start of the tensor object `r`, through the kernel's map
/// of it. The object is asked for by reference at every access (a stale one,
/// or one the kernel may not touch, answers `false`).
fn put_words(r: u32, words: &[u32]) -> bool {
    let bytes = 4 * words.len();
    // SAFETY: `memobj_with_span_ref` hands the kernel address of the first
    // `bytes` bytes of a one-page, read-write object this task made, valid for
    // the closure (the region table is locked across it); the stores stay
    // inside it. The service maps the same page, so they are volatile.
    let wrote = memobj_with_span_ref(r, bytes, |base| unsafe {
        let p = base as *mut u32;
        for (i, w) in words.iter().enumerate() {
            p.add(i).write_volatile(w.to_le());
        }
    });
    matches!(wrote, Ok(Some(())))
}

/// The first `N` words of the tensor object `r`; `None` as for [`put_words`].
fn get_words<const N: usize>(r: u32) -> Option<[u32; N]> {
    // SAFETY: as in `put_words`; the loads stay inside the `4 * N` bytes.
    match memobj_with_span_ref(r, 4 * N, |base| unsafe {
        let p = base as *const u32;
        core::array::from_fn(|i| u32::from_le(p.add(i).read_volatile()))
    }) {
        Ok(Some(w)) => Some(w),
        _ => None,
    }
}

impl TensorMem for Mem {
    fn prepare(&mut self, input: [u32; 4]) -> bool {
        // The output starts as NaN: an `OK` that wrote nothing is not a class.
        put_words(self.input, &input) && put_words(self.output, &[POISON_BITS; OUTPUT_BYTES / 4])
    }

    fn output(&mut self) -> Option<[u32; 3]> {
        get_words(self.output)
    }
}

/// What the helper holds for the life of the boot.
struct Client {
    mem: Mem,
    input: Cap<Tensor>,
    output: Cap<Tensor>,
}

impl Client {
    /// Make the two one-page tensor objects. The helper owns them, so the
    /// service's copies lapse with its unmap and the objects stay.
    fn new(tid: u32) -> Option<Client> {
        let spec = MemSpec::anon(MemPerms::ReadWrite);
        let input = memobj_create_cap(tid, 1, &spec).ok()?;
        let output = memobj_create_cap(tid, 1, &spec).ok()?;
        let input_r = azos_ipc::cap_store::get(tid, input, CapPerms::READ).ok()?;
        let output_r = azos_ipc::cap_store::get(tid, output, CapPerms::READ).ok()?;
        Some(Client {
            mem: Mem { input: input_r, output: output_r },
            input: Cap::from_raw(input.raw().0),
            output: Cap::from_raw(output.raw().0),
        })
    }

    /// One call. The capability is looked up (or minted) every time: an
    /// endpoint that was torn down and made again with the restarted service
    /// is a new object, and a handle kept from before the restart would name
    /// the dead one for ever.
    fn call(&mut self, front_mm: u16, right_mm: u16, deadline_ns: u64) -> Attempt {
        let Some(h) = kcall::endpoint_handle_badged(INFER_ENDPOINT, BEHAVIOR_BADGE) else {
            return Attempt::missing(MlOutcome::Unavailable, Why::NotReady);
        };
        behavior_infer::infer_once(
            KernelEndpoint(h),
            &mut self.mem,
            self.input,
            self.output,
            BEHAVIOR_MODEL_REF,
            deadline_ns,
            front_mm,
            right_mm,
        )
    }
}

fn wake_helper() {
    let tid = HELPER_TID.load(Ordering::Acquire);
    if tid != 0 {
        let _ = azos_sched::scheduler::wake_task_by_tid(tid, &|r| matches!(r, WaitReason::Timer(d) if *d == PARK));
    }
}

fn wake_waiter() {
    let (tid, deadline) = (WAITER_TID.load(Ordering::Acquire), WAITER_DEADLINE.load(Ordering::Acquire));
    if tid != 0 {
        let _ = azos_sched::scheduler::wake_task_by_tid(tid, &|r| matches!(r, WaitReason::Timer(d) if *d == deadline));
    }
}

/// The `ml-infer` task: sets up, then answers requests one at a time for ever.
fn infer_task(_: usize) {
    let tid = azos_sched::current_task_tid();
    HELPER_TID.store(tid, Ordering::Release);
    let Some(mut client) = Client::new(tid) else {
        HELPER.store(HELPER_FAILED, Ordering::Release);
        azos_drv_sys::kwarn!("[ML] no tensor memory objects for the Infer client: no ML verdicts this boot, \
                   L1 holds STOP");
        return;
    };
    HELPER.store(HELPER_READY, Ordering::Release);
    let mut served = 0u32;
    loop {
        let seq = REQUEST.load(Ordering::Acquire);
        if seq == served {
            let _ = azos_sched::task_block_outcome(WaitReason::Timer(PARK));
            continue;
        }
        served = seq;
        let readings = REQ_READINGS.load(Ordering::Relaxed);
        let attempt = client.call(readings as u16, (readings >> 16) as u16, REQ_DEADLINE_NS.load(Ordering::Relaxed));
        *RESULT.lock() = Some((seq, attempt));
        DONE.store(seq, Ordering::Release);
        wake_waiter();
    }
}

// ── The loop's side ──────────────────────────────────────────────────────

/// The wait of the loop: a timer, ended by the helper's wake.
struct LoopWait;

impl ReplyWaitEnv for LoopWait {
    fn now(&self) -> u64 {
        azos_drv_sys::timebase::now()
    }
    fn block(&self, deadline: u64) -> bool {
        azos_sched::task_block_outcome(WaitReason::Timer(deadline)) == BlockOutcome::Refused
    }
}

/// One request to the service, answered within [`ML_REPLY_TIMEOUT_US`] or
/// not at all.
fn call(front_mm: u16, right_mm: u16) -> Attempt {
    if service_tid() == 0 {
        return Attempt::missing(MlOutcome::NotLaunched, Why::NotReady);
    }
    if HELPER.load(Ordering::Acquire) != HELPER_READY {
        return Attempt::missing(MlOutcome::Unavailable, Why::NotReady);
    }
    let seq = REQUEST.load(Ordering::Relaxed);
    if DONE.load(Ordering::Acquire) != seq {
        // The previous call is still out: no second one behind it.
        return Attempt::missing(MlOutcome::Late, Why::Pending);
    }
    let seq = seq.wrapping_add(1);
    let now = azos_drv_sys::timebase::now();
    let timeout = azos_drv_sys::timebase::TIMER_FREQ.saturating_mul(ML_REPLY_TIMEOUT_US) / 1_000_000;
    let deadline = now.saturating_add(timeout);
    REQ_READINGS.store(front_mm as u32 | (right_mm as u32) << 16, Ordering::Relaxed);
    REQ_DEADLINE_NS.store(
        azos_abi::time::ticks_to_ns(now, azos_drv_sys::timebase::TIMER_FREQ).saturating_add(ML_REPLY_TIMEOUT_US * 1000),
        Ordering::Relaxed,
    );
    WAITER_DEADLINE.store(deadline, Ordering::Relaxed);
    WAITER_TID.store(azos_sched::current_task_tid(), Ordering::Release);
    REQUEST.store(seq, Ordering::Release);
    wake_helper();
    match wait_for_reply(&LoopWait, deadline, || DONE.load(Ordering::Acquire) == seq, || {}) {
        WaitOutcome::Replied => match *RESULT.lock() {
            Some((n, a)) if n == seq => a,
            _ => Attempt::missing(MlOutcome::Malformed, Why::NotReady),
        },
        WaitOutcome::TimedOut | WaitOutcome::Refused => {
            Attempt::missing(MlOutcome::Late, Why::Transport(azos_devif::IdlError::DeadlineExpired))
        }
    }
}

/// The loop's per-cycle state: outcome counts and the one-shot lines.
pub struct MlLink {
    pub stats: MlLinkStats,
    absence: MlAbsence,
    said_verdict: bool,
    said_missing: bool,
    /// The model that answered the latest cycle; `ModelRecord::NONE` when that
    /// cycle had no verdict.
    model: ModelRecord,
}

impl MlLink {
    pub const fn new() -> Self {
        MlLink {
            stats: MlLinkStats::new(),
            absence: MlAbsence::new(),
            said_verdict: false,
            said_missing: false,
            model: ModelRecord::NONE,
        }
    }

    /// The model that produced the verdict of the latest [`MlLink::cycle`]
    /// (`ModelRecord::NONE` when there was none): the part of the motor
    /// command's record that says what decided it.
    pub fn model(&self) -> ModelRecord {
        self.model
    }

    /// This cycle's request: the MLP on the two range readings.
    pub fn cycle(&mut self, front_mm: u16, right_mm: u16) -> MlOutcome {
        let a = call(front_mm, right_mm);
        let outcome = a.outcome;
        self.stats.note(outcome);
        self.model = match (outcome, a.why) {
            (MlOutcome::Verdict(_), Why::Served) => ModelRecord {
                model_hash: a.done.model_hash,
                variant_id: a.done.variant_id,
                backend: a.done.backend,
            },
            _ => ModelRecord::NONE,
        };
        match outcome {
            MlOutcome::Verdict(c) if !self.said_verdict => {
                self.said_verdict = true;
                kprintln!("[BEHAVIOR][ML] first ring-3 verdict: class={} from mlsrv tid={} model={:#018x} \
                           variant={} backend={} (front={} right={} logits {:#010x} {:#010x} {:#010x})",
                    c, service_tid(), a.done.model_hash, a.done.variant_id, a.done.backend,
                    front_mm, right_mm, a.logits[0], a.logits[1], a.logits[2]);
            }
            MlOutcome::Late | MlOutcome::Unavailable | MlOutcome::Malformed | MlOutcome::NotLaunched
                if !self.said_missing =>
            {
                self.said_missing = true;
                azos_drv_sys::kwarn!("[BEHAVIOR][ML] no verdict ({:?}: {:?}) -- L1 holds STOP {}", outcome, a.why,
                    if outcome == MlOutcome::NotLaunched { "while ML is enabled" }
                    else { "until mlsrv answers" });
            }
            _ => {}
        }
        outcome
    }

    /// The verdict L1 acts on for this cycle's `outcome`
    /// (`ml_link::mlp_result_for`), and the absence record when this cycle
    /// completes a run of missing verdicts (`ml_link::MlAbsence`).
    pub fn verdict(&mut self, outcome: MlOutcome) -> MlpResult {
        let r = azos_behavior::ml_link::mlp_result_for(outcome);
        if let Some(action) = self.absence.note(outcome, &r) {
            azos_behavior::logger::log_safety_violation(
                azos_behavior::logger::SAFETY_ML_ABSENT, action, service_tid());
            azos_drv_sys::kwarn!("[SAFETY] no ML verdict for {} cycles ({:?}): L1 holds STOP -- recorded \
                       (SAFETY_ML_ABSENT action={} tid={})",
                azos_behavior::ml_link::ABSENT_RECORD_CYCLES, outcome, action, service_tid());
        }
        r
    }

    #[cfg_attr(not(feature = "qemu"), allow(dead_code))]
    pub fn report(&self) {
        let s = &self.stats;
        kprintln!("[BEHAVIOR][ML] mlsrv tid={} verdicts={} late={} unavailable={} malformed={} \
                   not_launched={} (fallback STOP on {})",
            service_tid(), s.verdicts, s.late, s.unavailable, s.malformed, s.not_launched,
            s.fallbacks());
    }
}
