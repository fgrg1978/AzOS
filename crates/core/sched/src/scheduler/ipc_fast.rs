// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! IPC fast hand-off half of the scheduler: `ipc_wake_then_block`, the fast
//! path's claim and hand-off, resume points, and the direct switch. Child of
//! `scheduler` (moved out of `scheduler/mod.rs` unchanged).

use super::*;

/// Fast-IPC hand-off: wake `tid` (blocked on a reason `pred` accepts), then
/// block the current task on `reason` — **switching straight to `tid` on this
/// hart when that is exactly what `do_schedule` would have done.**
///
/// Observably the same as `wake_task_by_tid_ipc(tid, pred)` followed by
/// `task_block(reason)`, which is what it does whenever the direct path does
/// not apply. The direct path skips three things and nothing else: enqueueing
/// the woken task, `do_schedule`'s pick (deadline check, dequeue, priority
/// guard), and the spin gate on the woken task's `context_saving`. The gate is
/// replaced by a refusal: the claim re-reads `context_saving` with `Acquire`
/// AFTER its dispatch CAS and does not claim a task still being saved. The
/// `saved` flag `wake_transition` is given is read BEFORE that CAS and is NOT
/// proof — a server that blocked on another hart an instant earlier is
/// `Blocked` while that hart is still storing its registers. Trusting it was
/// measured: 1 aarch64 `ipctest -smp 4` run in 10 died with a jump into
/// `_text_end + 0x3e01` (a half-saved context resumed). A task that is
/// `Ready` and in no queue cannot start saving again, so one check suffices.
///
/// # The four outcomes, and why each is the old sequence
///
/// 1. The wake does not dispatch (stamped / mismatch / absent): nothing was
///    claimed; `block_current` runs exactly as before.
/// 2. The wake dispatches but [`ipc_direct::allowed`] refuses: the wake
///    enqueued the task itself (`WakeOut::Enqueued`); `block_current` as before.
/// 3. The wake claims the task, but the caller's own commit to `Blocked`
///    fails because a wake was already stamped on it: the caller does not
///    sleep, so the claimed task is enqueued where the ordinary IPC wake puts
///    it and the caller returns to re-check its condition — the same
///    `!committed` return `block_current` makes.
/// 4. Claimed and committed: the caller is switched out and the claimed task
///    in, with every step of `do_schedule`'s dispatch tail repeated here.
///
/// # Lock order ([`crate::wait`]'s K-C10 notes, and the direct hand-off that
/// was reverted)
///
/// The caller must hold no lock: `FAST_IPC` in particular is released before
/// this is called (the switched-to server's first act is to take it). A
/// held spinlock shows as `preempt::disabled()`, which sends this down the
/// old path, where `block_current`'s K-C29 refusal handles it as before. No
/// scheduler lock is taken on the direct path: the claim is the
/// `wake_transition` CAS, and `ready_bitmap` is read unlocked — a task
/// enqueued here by another hart after that read raises this hart's IPI and
/// preempts on its arrival, exactly as if it had been enqueued a moment later.
pub fn ipc_wake_then_block(
    tid: u32,
    pred: &dyn Fn(&WaitReason) -> bool,
    reason: WaitReason,
) {
    let cpu = current_cpu_id();
    #[cfg(feature = "sched-ipc-affinity")]
    if cpu < MAX_CPUS && !azos_sync::preempt::disabled() {
        // IRQs off from the claim to the switch: a tick in between would run
        // `do_schedule` on this hart with the claimed task in no queue.
        let sstatus = azos_arch::ARCH.disable_all();
        match wake_by_slot(idx_for_tid(tid), pred, true, cpu) {
            // SAFETY: `cpu < MAX_CPUS`; `ti` came from `idx_for_tid` and was
            // just claimed by this hart's CAS, so nothing else dispatches it.
            WakeOut::Claimed(ti) => unsafe { direct_switch_block::<false>(cpu, ti, reason) },
            WakeOut::Enqueued | WakeOut::NotWoken => {
                azos_arch::ARCH.restore(sstatus);
                block_current(cpu, reason);
                return;
            }
        }
        azos_arch::ARCH.restore(sstatus);
        return;
    }
    wake_task_by_tid_ipc(tid, pred);
    block_current(cpu, reason);
}

/// `SYS_IPC_FAST_CALL`'s hand-off: wake the server blocked in accept, then
/// sleep on the reply to `handle`. The two predicates are the ones
/// `wait::wake_fast_ipc_server` and the caller's own `task_block` use.
pub fn fast_ipc_call_handoff(server_tid: u32, handle: u64) {
    ipc_wake_then_block(
        server_tid,
        &|r| matches!(r, WaitReason::FastIpcServer(tid) if *tid == server_tid),
        WaitReason::FastIpcClient(handle),
    );
}

/// `SYS_IPC_FAST_REPLY_ACCEPT`'s hand-off: wake the client whose exchange
/// `handle` was just answered, then sleep as `server_tid` waiting for the next
/// call. The predicates are `wait::wake_fast_ipc_client_tid`'s and the
/// accept's own `task_block`.
pub fn fast_ipc_reply_handoff(caller_tid: u32, handle: u64, server_tid: u32) {
    ipc_wake_then_block(
        caller_tid,
        &|r| matches!(r, WaitReason::FastIpcClient(h) if *h == handle),
        WaitReason::FastIpcServer(server_tid),
    );
}

// ── The IPC fast path's scheduler half (Kconfig IPC_FASTPATH, Chain E a) ───
//
// `azos_syscall::fastpath` finishes a fast call or reply whose peer is parked
// in the matching wait. It claims the peer itself, under the endpoint lock and
// as that lock's last step, with [`ipc_fast_claim`] (a claim that fails must
// leave nothing behind, so it never stamps), then hands off with
// [`ipc_fast_handoff`], which is [`ipc_wake_then_block`]'s tail for a peer
// that is already `Ready`: the same dispatch bookkeeping, the same
// `ipc_direct::allowed` decision, and either the same direct switch or the
// same enqueue followed by `block_current`.
//
// Resume points (Kconfig IPC_FASTPATH_RESUME, Chain E commit 9). A task about
// to block in [`ipc_fast_handoff`] may leave a [`FastResume`] ([`ipc_fast_leave`]):
// where its syscall's exit is. The fast path's claim of that task takes the
// point ([`ipc_fast_take_resume`]) and, when it has finished the task's
// syscall for it (its answer written into the task's own registers), starts
// the task there ([`ipc_fast_start_at`]): its saved `context.sp`/`pc` are
// rewritten while it is claimed (no CPU can run it), so whichever switch runs
// it next, the hand-off's own or the scheduler's, starts it at its exit and
// not on the hand-off's return path (`finish_switch`, which the point's code
// makes, and, after a `block_current`, its interrupt restore, which the exit
// makes from the frame). Every other resume (a wake by a drain, a kill, an
// ordinary call or reply, a timeout), and a hand-off that did not sleep at
// all, finds the context as the task saved it and returns from the hand-off,
// where the task spends the point (`direct_switch_block::<true>`, and after
// the hand-off's `block_current`). Nothing is restored: a point is rewritten
// into the context only by its last claim.

/// Whether this build has the fast path's hand-off: the direct switch it
/// reuses is `sched-ipc-affinity`'s.
pub const IPC_FAST: bool = cfg!(feature = "sched-ipc-affinity");

/// Whether this build has resume points (Kconfig IPC_FASTPATH_RESUME). Not
/// with `switch-census` or `ipc-census`: their counters count steps of the
/// hand-off's return path (`swcensus::after_switch`, `BLOCK_SLEPT`), which a
/// task started at its point does not take.
pub const IPC_FAST_RESUME: bool = IPC_FAST
    && azos_limits::IPC_FASTPATH_RESUME
    && !cfg!(feature = "switch-census")
    && !cfg!(feature = "ipc-census");

/// Whether a resume point's exit always calls [`azos_ipc_fast_exit`]: the
/// checks it runs there are in this build (lockdep's no-lock check on the
/// return to user mode, `ctx-probe`'s resume check). Otherwise only a
/// pending reap calls it. The ISAs' resume stubs take it as
/// `{resume_exit_call}`.
pub const IPC_FAST_EXIT_CALL: bool = azos_sync::lockdep::ON || cfg!(feature = "ctx-probe");

/// A task's resume point (see the section comment above): the code to start
/// it at (`pc`, never 0 for a point) and the stack pointer to start it with
/// (`sp`: the syscall's register frame the code returns through). The code
/// runs as the task, interrupts off, with every step of the dispatch made,
/// and before anything else does what the switch's own return would
/// ([`azos_ipc_fast_resumed`]; a user task's stub through
/// [`azos_ipc_fast_exit`], when `reap_on_resume` is set or the build has
/// return-to-user checks).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FastResume {
    pub sp: usize,
    pub pc: usize,
}

impl FastResume {
    /// No resume point: resume where the task blocked.
    pub const NONE: Self = Self { sp: 0, pc: 0 };
}

/// What a spent resume point's `pc` becomes: 0, or with the runtime canary
/// `ipc-resume-stale` 1 (a task resumed where it blocked is left holding a
/// point, one no claim can use: the break the resume-point ktests must see).
/// A load and not a test, so the spend is three instructions. Boot only.
static RESUME_SPENT: AtomicUsize = AtomicUsize::new(0);

/// Arm the runtime canary `ipc-resume-stale`.
pub fn canary_ipc_resume_stale() {
    RESUME_SPENT.store(1, Ordering::Relaxed);
}

/// The current task, in slot `ti`, is about to block in [`ipc_fast_handoff`]
/// and leaves `point` (`pc != 0`) for the claim that may finish its syscall.
/// Written before the hand-off publishes its saved context
/// (`context_saving`'s release), so a hart that claims it reads it; until the
/// task is `Blocked` and saved no claim can take it.
#[inline(always)]
pub fn ipc_fast_leave(ti: usize, point: FastResume) {
    if IPC_FAST_RESUME && ti < MAX_TASKS {
        // SAFETY: `ti < MAX_TASKS`, the current task's own slot.
        unsafe {
            let t = task_mut(ti);
            t.fast_resume_sp = point.sp;
            t.fast_resume_pc = point.pc;
        }
    }
}

/// The current task on hart `cpu` is back from [`ipc_fast_handoff`]'s
/// `block_current` where it blocked (or never slept): a point it left is
/// spent, so no later claim finds it where it next blocks. Its only caller is
/// the hand-off, which is `sched-ipc-affinity`'s.
#[cfg(feature = "sched-ipc-affinity")]
#[inline(always)]
fn ipc_fast_spend_current(cpu: usize) {
    if !IPC_FAST_RESUME || cpu >= MAX_CPUS {
        return;
    }
    // SAFETY: `cpu < MAX_CPUS`; the current task's own slot.
    unsafe {
        let cur = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if cur < MAX_TASKS {
            task_mut(cur).fast_resume_pc = RESUME_SPENT.load(Ordering::Relaxed);
        }
    }
}

/// Does the task in slot `ti` hold a resume point? A hint, read without the
/// claim (the fast path's choice of claim); [`ipc_fast_take_resume`] decides.
#[inline(always)]
pub fn ipc_fast_marked(ti: usize) -> bool {
    // SAFETY: `ti < MAX_TASKS`; a word-sized read of a hint.
    IPC_FAST_RESUME && ti < MAX_TASKS && unsafe { core::ptr::read_volatile(&task_ref(ti).fast_resume_pc) } != 0
}

/// Does the task in slot `ti` hold a resume point (it is blocked in the fast
/// path's hand-off, or the canary left one)? For the ktests.
pub fn ipc_fast_resume_held(ti: usize) -> bool {
    // SAFETY: `ti < MAX_TASKS`; a word-sized read for a test's verdict.
    ti < MAX_TASKS && unsafe { core::ptr::read_volatile(&task_ref(ti).fast_resume_pc) } != 0
}

/// Is the task in slot `ti` blocked, on anything? For the ktests: a task's
/// point is written before it reads as blocked.
pub fn ipc_fast_blocked(ti: usize) -> bool {
    use crate::task::sched_word::{pack, STATE_MASK};
    // SAFETY: `ti < MAX_TASKS`; a word-sized read for a test's verdict.
    ti < MAX_TASKS
        && unsafe { task_ref(ti).state_word.load(Ordering::Acquire) } & STATE_MASK == pack(TaskState::Blocked)
}

/// Take the resume point of the task in slot `ti`, which the caller claimed
/// with [`ipc_fast_claim`], which found it saved (interrupts off, the task in
/// no queue, no hart saving its registers): the point
/// it left, or [`FastResume::NONE`] when it left none or its syscall has exit
/// work of its own (an exec hand-off). The point is spent either way: the
/// caller starts the task there ([`ipc_fast_start_at`]) once it has finished
/// the task's syscall for it, or leaves it to resume where it blocked.
#[inline(always)]
pub fn ipc_fast_take_resume(ti: usize) -> FastResume {
    if !IPC_FAST_RESUME || ti >= MAX_TASKS {
        return FastResume::NONE;
    }
    // SAFETY: `ti < MAX_TASKS`, claimed by the caller: no CPU runs it, and
    // its point was written before its saved context was published (the
    // claim read `context_saving` false with Acquire after its CAS).
    unsafe {
        let t = task_mut(ti);
        let point = FastResume { sp: t.fast_resume_sp, pc: t.fast_resume_pc };
        if point.pc == 0 {
            return FastResume::NONE;
        }
        t.fast_resume_pc = 0;
        if t.exec_ctx_ready.load(Ordering::Relaxed) {
            return FastResume::NONE;
        }
        point
    }
}

/// Start the claimed task in slot `ti` at `point` (one [`ipc_fast_take_resume`]
/// returned for it) whenever it next runs: its syscall is over, its registers
/// written. The caller then dispatches it as before.
#[inline(always)]
pub fn ipc_fast_start_at(ti: usize, point: FastResume) {
    if !IPC_FAST_RESUME || ti >= MAX_TASKS || point.pc == 0 {
        return;
    }
    // SAFETY: as in `ipc_fast_take_resume`; nothing reads `sp`/`pc` of a
    // saved context but the `context_switch` that next runs the task.
    unsafe {
        let t = task_mut(ti);
        t.context.sp = point.sp as CtxReg;
        t.context.pc = point.pc as CtxReg;
    }
}

/// A user task started at its resume point (an ISA's resume stub), on its
/// way to the syscall exit: [`azos_ipc_fast_resumed`], then the check the
/// trap handler's return to user mode makes in this build (lockdep's no lock
/// held). Called when `reap_on_resume` is set, or always with
/// [`IPC_FAST_EXIT_CALL`]; interrupts off, on the task's own stack.
#[unsafe(no_mangle)]
pub extern "C" fn azos_ipc_fast_exit() {
    azos_ipc_fast_resumed();
    azos_sync::lockdep::user_return();
}

/// What a task started at its resume point owes before anything else: the
/// switch's own return path's step (`finish_switch`: the reap of a Zombie
/// the switch left, and `ctx-probe`'s check), which its resume point skips.
/// On the task's own stack, interrupts off.
#[unsafe(no_mangle)]
pub extern "C" fn azos_ipc_fast_resumed() {
    let cpu = current_cpu_id();
    if cpu >= MAX_CPUS {
        return;
    }
    // SAFETY: `cpu < MAX_CPUS`; the current task, on its own stack.
    unsafe {
        let cur = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        if cur < MAX_TASKS {
            finish_switch(task_mut(cur) as *mut Task);
        }
    }
}

/// `a == b` for the two reasons the fast path parks on, written out: the
/// derived `PartialEq` was an out-of-line call on every claim. Any other
/// reason compares unequal (the fast path never asks for one).
#[inline(always)]
fn same_ipc_wait(a: &WaitReason, b: &WaitReason) -> bool {
    match (a, b) {
        (WaitReason::FastIpcServer(x), WaitReason::FastIpcServer(y)) => x == y,
        (WaitReason::FastIpcClient(x), WaitReason::FastIpcClient(y)) => x == y,
        _ => false,
    }
}

/// Is the task in slot `ti`, TID `tid`, parked on exactly `want`: `Blocked`
/// with no stamp, and its registers saved? A lock-free hint the fast path
/// reads before it takes the endpoint lock; [`ipc_fast_claim`] decides.
#[inline(always)]
pub fn ipc_fast_parked(ti: usize, tid: u32, want: WaitReason) -> bool {
    use crate::task::sched_word::{pack, WAKE_STAMP};
    if ti >= MAX_TASKS {
        return false;
    }
    // SAFETY: `ti < MAX_TASKS`; read only. `wait_reason` is read only under
    // an observed `Blocked` (Acquire), as every waker's predicate reads it.
    unsafe {
        let t = task_ref(ti);
        TASK_VALID[ti].load(Ordering::Relaxed)
            && t.tid == tid
            && t.state_word.load(Ordering::Acquire) & (crate::task::sched_word::STATE_MASK | WAKE_STAMP)
                == pack(TaskState::Blocked)
            && same_ipc_wait(&t.wait_reason, &want)
            && !t.context_saving.load(Ordering::Acquire)
    }
}

/// Claim the task in slot `ti` for the fast path: its `Blocked -> Ready`
/// CAS, taken only when it is `Blocked` on exactly `want` with no stamp and
/// its registers saved (`task::sched_word::fast_claim`). On `Some(saved)`
/// the caller owns its dispatch exactly as a waker that won
/// `wake_transition`'s CAS does, and must call [`ipc_fast_handoff`]
/// (interrupts stay off from here to there); `saved` is `context_saving`
/// read after the CAS, and only a saved task's resume point may be taken
/// ([`ipc_fast_take_resume`]). On `None` nothing was written: unlike
/// `wake_transition`, a task that is not parked is not stamped, because the
/// fast path then leaves the call to the ordinary path, which wakes it.
///
/// The hand-off reads `context_saving` after the CAS too (`dispatched`,
/// `target_saved`): an unsaved task is enqueued, not switched to.
#[inline(always)]
pub fn ipc_fast_claim(ti: usize, want: WaitReason) -> Option<bool> {
    if ti >= MAX_TASKS {
        return None;
    }
    // SAFETY: `ti < MAX_TASKS`. The fields read are the ones every waker
    // reads (see `ipc_fast_parked`); the only write is the CAS.
    unsafe {
        let t = task_ref(ti);
        crate::task::sched_word::fast_claim(
            &t.state_word, || same_ipc_wait(&t.wait_reason, &want), &t.context_saving, || {},
        )
    }
}

/// The fast path's hand-off: `ti` was claimed on hart `cpu` with
/// [`ipc_fast_claim`] (interrupts off since before the claim, `irq` the state
/// to put back); dispatch it and block the current task on `reason`. This is
/// [`ipc_wake_then_block`] from its claim on: `dispatched` (the wake's own
/// bookkeeping and the `ipc_direct::allowed` decision) and then the direct
/// switch, or the enqueue and an ordinary `block_current`. Returns when the
/// current task runs again where it blocked (or, when it left a resume
/// point, [`ipc_fast_leave`], perhaps never: see [`FastResume`]).
#[cfg(feature = "sched-ipc-affinity")]
#[inline(never)]
pub fn ipc_fast_handoff(cpu: usize, ti: usize, reason: WaitReason, irq: azos_arch_api::InterruptState) {
    if cpu >= MAX_CPUS || ti >= MAX_TASKS {
        // Unreachable: the claim bounds `ti` and the fast path read `cpu`
        // as `current_cpu_id()`. A claimed task is still never dropped.
        if ti < MAX_TASKS {
            // SAFETY: `ti < MAX_TASKS`, claimed by this hart.
            unsafe { direct_claim_enqueue(ti) };
        }
        azos_arch::ARCH.restore(irq);
        return;
    }
    // SAFETY: `cpu < MAX_CPUS`, `ti < MAX_TASKS`, and `ti` was claimed by
    // this hart's CAS, so nothing else dispatches it.
    unsafe {
        match dispatched(ti, task_mut(ti), true, cpu, attrib::Via::Ipc) {
            WakeOut::Claimed(ti) => direct_switch_block::<true>(cpu, ti, reason),
            WakeOut::Enqueued | WakeOut::NotWoken => {
                azos_arch::ARCH.restore(irq);
                block_current(cpu, reason);
                // Back where it blocked (or it never slept): a resume point
                // it left is spent (see `FastResume`).
                ipc_fast_spend_current(cpu);
                return;
            }
        }
    }
    azos_arch::ARCH.restore(irq);
}

/// Without `sched-ipc-affinity` there is no fast path ([`IPC_FAST`] is false
/// and `azos_syscall::fastpath` is compiled out); this keeps the name.
#[cfg(not(feature = "sched-ipc-affinity"))]
pub fn ipc_fast_handoff(_cpu: usize, _ti: usize, reason: WaitReason, irq: azos_arch_api::InterruptState) {
    azos_arch::ARCH.restore(irq);
    block_current(current_cpu_id(), reason);
}

/// Times [`ipc_wake_then_block`] switched directly (census builds only).
#[cfg(feature = "ipc-census")]
pub static IPC_DIRECT_SWITCHES: AtomicU32 = AtomicU32::new(0);

/// Claims [`ipc_wake_then_block`] declined because the woken task's
/// registers were still being saved on another hart (census builds only).
/// Non-zero proves the window the post-CAS re-read closes is really hit.
#[cfg(feature = "ipc-census")]
pub static IPC_DIRECT_UNSAVED: AtomicU32 = AtomicU32::new(0);

/// See [`IPC_DIRECT_SWITCHES`]; `0` on a kernel without `ipc-census`.
pub fn ipc_direct_switches() -> u32 {
    #[cfg(feature = "ipc-census")]
    { IPC_DIRECT_SWITCHES.load(Ordering::Relaxed) }
    #[cfg(not(feature = "ipc-census"))]
    { 0 }
}

/// See [`IPC_DIRECT_UNSAVED`]; `0` on a kernel without `ipc-census`.
pub fn ipc_direct_unsaved() -> u32 {
    #[cfg(feature = "ipc-census")]
    { IPC_DIRECT_UNSAVED.load(Ordering::Relaxed) }
    #[cfg(not(feature = "ipc-census"))]
    { 0 }
}

/// Outcomes 3 and 4 of [`ipc_wake_then_block`]. Called with IRQs masked and
/// `ti` claimed (`Ready`, `wait_reason` cleared, `tp == cpu`, in no queue,
/// histogram key not yet re-accounted).
///
/// `FAST`: the IPC fast path's own hand-off ([`ipc_fast_handoff`]); the task
/// spends a resume point it left (Kconfig IPC_FASTPATH_RESUME, see
/// [`FastResume`]) whenever it returns from here, slept or not.
#[cfg(feature = "sched-ipc-affinity")]
#[inline(always)]
unsafe fn direct_switch_block<const FAST: bool>(cpu: usize, ti: usize, reason: WaitReason) {
    unsafe {
        let cur = PER_CPU[cpu].current_idx.load(Ordering::Relaxed);
        // `wake_by_slot` only claims with a valid current (it read its
        // priority); `< MAX_TASKS` again lets the index below be proven.
        if cur >= MAX_TASKS {
            direct_claim_enqueue(ti);
            return;
        }
        let task = task_mut(cur);
        // Same three steps, same order, as `block_current`: in-transit mark,
        // reason, then the commit CAS that publishes `Blocked`.
        task.context_saving.store(true, Ordering::Relaxed);
        task.wait_reason = reason;
        let committed = crate::task::sched_word::commit_blocked_or_consume_wake(&task.state_word);
        if !committed {
            hist_reaccount(cur);
            // Outcome 3. We never became Blocked; undo the mark, and give the
            // claimed task to the run queue the ordinary wake would have used.
            #[cfg(feature = "ipc-census")]
            unswitched::bump(&unswitched::BLOCK_SKIPPED);
            task.context_saving.store(false, Ordering::Relaxed);
            direct_claim_enqueue(ti);
            if IPC_FAST_RESUME && FAST {
                task.fast_resume_pc = RESUME_SPENT.load(Ordering::Relaxed);
            }
            return;
        }

        // K-C24 rescue, as in `do_schedule`'s `Blocked` arm: a waker on
        // another hart that saw us `Blocked` with `context_saving` still set
        // stamped instead of dispatching. Consume that stamp into a normal
        // `Ready` + enqueue here, or it waits for the periodic reaper.
        loop {
            use crate::task::sched_word::{pack, WAKE_STAMP};
            let curw = task.state_word.load(Ordering::Acquire);
            if curw & WAKE_STAMP == 0
                || crate::task::sched_word::state_of(curw) != TaskState::Blocked
            {
                break;
            }
            if task.state_word.compare_exchange_weak(
                curw, pack(TaskState::Ready),
                Ordering::AcqRel, Ordering::Relaxed,
            ).is_ok() {
                hist_reaccount(cur);
                task.wait_reason = WaitReason::None;
                task.ready_site.store(
                    crate::task::ready_site::KC24_RESCUE | ((cpu as u8) << 4),
                    Ordering::Relaxed,
                );
                if !cpu_enqueue_locked(cpu, cur) {
                    SCHED_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
                }
                break;
            }
        }

        // Outcome 4: `do_schedule`'s dispatch tail for `next = ti`. The steps
        // it has that are absent here are excluded by `ipc_direct::allowed`
        // (the tickless re-arm on an idle switch) or do
        // not apply (the old task is not `Running` or `Zombie`).
        let next = task_mut(ti);
        #[cfg(feature = "ipc-census")]
        {
            wakelat::measure(ti);
            IPC_DIRECT_SWITCHES.fetch_add(1, Ordering::Relaxed);
            unswitched::bump(&unswitched::BLOCK_SLEPT);
            unswitched::bump(&unswitched::SWITCHED);
        }
        next.set_state(TaskState::Running);
        // One paired re-account for both transitions (this task's `Blocked`
        // commit above, the claimed task's `Running` here): on a same-hart,
        // same-bucket hand-off they cancel and the histogram is not touched.
        hist_reaccount_pair(cur, ti);
        set_current_task(cpu, ti);
        // As in `do_schedule`: the switching hart's id is the last `tp` store.
        next.context.tp = cpu as CtxReg;
        if azos_sync::preempt::disabled() {
            preempt_audit::bump(&preempt_audit::SWITCH_WHILE_ATOMIC);
            azos_sync::preempt::force_zero_depth();
        }
        if azos_limits::SCHED_SWITCH_COUNTERS {
            task.switches_voluntary.fetch_add(1, Ordering::Relaxed);
        }
        // This hand-off bypasses `do_schedule`'s dispatch tail,
        // so it closes and opens the two signals itself.
        #[cfg(feature = "energy")]
        energy::on_switch(cpu, cur, ti);
        // Wave 15 (TRACE): the direct IPC hand-off is a switch too (reason 2).
        // The state is an atomic load: read it only when recording, or the
        // compiled-out build would still pay it.
        if azos_trace::sched_on() {
            azos_trace::raw::sched_switch(task.tid, next.tid, task.state() as u32, 2);
        }
        #[cfg(feature = "ctx-probe")]
        ctx_probe::check_dispatch(ctx_probe::DIRECT, cpu, ti);
        // Lockdep: as in `do_schedule`'s tail (the blocked task runs again).
        azos_sync::lockdep::switch(Some(cur), ti);
        azos_sync::qsbr::switch();
        // N12: as in `do_schedule`'s tail.
        crate::asid::prepare_switch(next as *mut Task);
        context_switch(task as *mut Task, next as *mut Task);
        // Resumed: woken and dispatched like any other blocked task. Where it
        // blocked, so a resume point it left is spent (see `FastResume`).
        if IPC_FAST_RESUME && FAST {
            task.fast_resume_pc = RESUME_SPENT.load(Ordering::Relaxed);
        }
        finish_switch(task as *mut Task);
    }
}

/// Hand a claimed-but-unused task to the queue the ordinary IPC wake would
/// have chosen (outcome 3 of [`ipc_wake_then_block`]).
///
/// The waker did not block here (its block consumed a wake that was already
/// pending, or there is no current task to block), so unlike the synchronous
/// hand-off it keeps running: the enqueue goes through the wake-preemption
/// check (`wake_enqueue_preempting`), or a server of a better class queued on
/// this CPU would wait for the next tick behind its own client. The direct
/// switch, where the server runs at once, needs no check and has none.
#[cfg(feature = "sched-ipc-affinity")]
#[inline(never)]
unsafe fn direct_claim_enqueue(ti: usize) {
    unsafe {
        let t = task_mut(ti);
        let target_cpu = ipc_wake_target_cpu(ti, t);
        t.context.tp = target_cpu as CtxReg;
        hist_reaccount(ti);
        if !wake_enqueue_preempting(target_cpu, ti, true) {
            WAKE_ENQ_REFUSED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

