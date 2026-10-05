// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Async-runtime microbench (RFC-0030 / Idea 12).
//!
//! Measures the cost to **resume a cooperative `async` task** — one `poll()`
//! of a yielding state machine — which is the operation that *replaces* a
//! preemptive context switch in a stackless async control plane. Compare
//! against `sched.task_yield` (the full preemptive yield → schedule →
//! `context_switch` → register-file save/restore path, ~2200 cyc measured).
//!
//! This is the **structural floor** of cooperative scheduling: a `poll()` is a
//! plain function call into a monomorphised state machine — no 31-GPR + FP +
//! CSR save/restore, no scheduler bookkeeping. Pure compute → runs in the
//! quiescent early-boot bench (clean rdcycle, no scheduler needed).
//!
//! # ⚠️ Read this before quoting `asyncrt.poll_resume`
//!
//! RFC-0030 closed `deferred` on 2026-08-28. Two corrections to the paragraph
//! above, both established by disassembling this file's own output — see that
//! RFC's §Results §2 and §4 for the evidence:
//!
//! 1. **This bench does not measure a `poll()` call.** At `-O` the optimiser
//!    inlines `Future::poll` into the loop and folds the future away. The
//!    measured region compiles to **five RV64 instructions** — `snez`, `sb`
//!    (the `black_box` store), `addi`, `sub`, `bnez` — with **no `jalr`**, no
//!    `Pin` deref, no `Context`/`Waker` touch and no state-machine dispatch.
//!    It is a decrement, not a task resume. A real executor's resume must also
//!    pay an indirect call, waker/ready-bitmap plumbing, a discriminant
//!    dispatch, and reloads of locals held live across `.await`.
//! 2. **Never divide this number by `sched.task_yield`.** They are captured on
//!    different substrates and the ratio is undefined: `poll_resume` only runs
//!    from `run_all_quiescent` (hart 0 alone, timer ISR off), while
//!    `task_yield` is *excluded* from that path and only runs from `run_all`
//!    on a live SMP-4 system. Under TCG all harts share one host thread, so
//!    `rdcycle` advances through other harts' work — the confound that
//!    rejected RFC-0027. The historical "8.8× cheaper" figure is retracted for
//!    exactly this reason.
//!
//! Also note `rdcycle` here is a coarse host wall-clock: totals quantise to
//! multiples of 1000, so ~200 "cycles" for five instructions is resolution,
//! not cost.
//!
//! **Why this file is kept anyway:** it is the recorded zero-work control for
//! the follow-up experiment RFC-0030 §Results §7 step 3 — when a real
//! cooperative executor lands, its honest per-resume instruction count has to
//! be measured against this baseline. Gated behind the `asyncrt` cargo
//! feature; zero cost in any build that does not enable it.

use crate::{BenchResult, report, best_of};
use azos_drv_sys::wcet::read_cycles;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

/// Minimal no-op waker (no executor / no wake list — we poll directly).
fn noop_raw_waker() -> RawWaker {
    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker { noop_raw_waker() }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
    RawWaker::new(core::ptr::null(), &VTABLE)
}

/// A future that yields (`Pending`) `n` times before completing. Each poll
/// resumes from the prior await point and yields again — modelling the
/// per-tick "resume a cooperative control task" the async plane would do.
struct CountdownYield {
    n: u64,
}

impl Future for CountdownYield {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        if self.n == 0 {
            Poll::Ready(())
        } else {
            self.n -= 1;
            Poll::Pending
        }
    }
}

/// Per-resume cost: poll a yielding future `iters` times (each poll = one
/// cooperative resume).
pub fn bench_poll_resume(iters: u64) -> BenchResult {
    // SAFETY: noop waker holds no state; vtable is 'static.
    let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = CountdownYield { n: iters + 1 };
    // SAFETY: `fut` lives on this stack frame and is never moved after pinning.
    let mut pinned = unsafe { Pin::new_unchecked(&mut fut) };

    let start = read_cycles();
    for _ in 0..iters {
        let _ = core::hint::black_box(pinned.as_mut().poll(&mut cx));
    }
    let end = read_cycles();
    BenchResult::from_total(start, end, iters)
}

pub fn run(iters: u64) -> u32 {
    report("asyncrt.poll_resume", &best_of(|| bench_poll_resume(iters)));
    1
}
