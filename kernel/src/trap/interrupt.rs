// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! riscv64 trap init and interrupt dispatch: `trap_init`, the timer/external/
//! software interrupt arms, and the deferred reschedule `trap_resched` that
//! `trap_entry.S` calls on the interrupt path. The interrupt-stack helpers
//! live here too: two of them run on that path, and keeping them in this
//! module keeps them inlinable into it.

use crate::*;

/// Arm the boot hart's interrupt stack (its magic word and its entry in
/// `AZOS_IRQ_STACK_BASE`).
///
/// Called once by the boot hart before interrupts are enabled anywhere. The
/// secondaries' stacks live in their per-CPU areas and are armed by
/// `boot::setup_per_cpu_areas`, before the secondaries are started: a
/// secondary that took its first timer before its stack was armed would
/// find no stack (`trap_entry.S` then stays on the interrupted one).
#[cfg(target_arch = "riscv64")]
pub(crate) fn irq_stacks_arm() {
    use azos_arch::{Cpu, ARCH};
    crate::boot::arm_irq_stack(ARCH.percpu_base(), crate::boot::boot_irq_stack_base());
}

/// Print, once per boot, whether an interrupt really is being handled on the
/// hart's own interrupt stack.
///
/// The switch is a handful of instructions in `trap_entry.S` and it is easy
/// to read the disassembly and believe it. This asserts it from inside a live
/// handler instead: `sp` here belongs to whatever stack the handler is
/// running on. `[IRQSTACK] FAILED:` is caught by the gate's global failure
/// pattern.
#[cfg(target_arch = "riscv64")]
pub(crate) fn irq_stack_probe(hart: usize) {
    use core::sync::atomic::{AtomicBool, Ordering};
    static PROBED: AtomicBool = AtomicBool::new(false);
    if PROBED.swap(true, Ordering::AcqRel) || hart >= MAX_HARTS { return; }
    let sp: usize;
    unsafe { core::arch::asm!("mv {}, sp", out(reg) sp, options(nomem, nostack)) };
    let base = crate::boot::irq_stack_base(hart);
    if base != 0 && sp >= base && sp < base + IRQ_STACK_SIZE {
        kprintln!("[IRQSTACK] hart {} handles interrupts on its own stack", hart);
    } else {
        azos_drv_sys::kerr!("[IRQSTACK] FAILED: hart {} handled an interrupt at sp {:#x}, \
                   outside its stack {:#x}..{:#x}", hart, sp, base, base + IRQ_STACK_SIZE);
    }
}

/// True while this hart's interrupt stack still carries its magic word.
#[cfg(target_arch = "riscv64")]
#[inline]
pub(crate) fn irq_stack_intact(hart: usize) -> bool {
    crate::boot::irq_stack_magic_intact(hart)
}

/// Initialize trap handling: set stvec, sscratch, scounteren.
#[cfg(target_arch = "riscv64")]
pub(crate) fn trap_init() {
    unsafe extern "C" { fn trap_vector(); }
    let trap_addr = trap_vector as *const () as usize;
    assert!(trap_addr & 0x3 == 0, "trap_vector not aligned");
    csr::write_stvec(trap_addr);
    csr::write_sscratch(0);
    csr::write_scounteren(0x7);
    kprintln!("[TRAP] Trap vector: {:#x}", csr::read_stvec());
}

/// Per-hart "an interrupt wants the scheduler" flag.
///
/// The timer and IPI branches of `handle_interrupt` used to call
/// `schedule()` themselves. They cannot any more: since 2026-09-16 a handler
/// runs on this hart's interrupt stack, and `context_switch` parks a task by
/// saving `sp` into its TCB -- a task parked with `sp` inside a stack shared
/// by every interrupt on the hart is a task whose frame the next interrupt
/// overwrites. So they raise this instead, and `trap_resched` spends it from
/// `trap_after_handler`, where `sp` is back on the task's own stack.
#[cfg(target_arch = "riscv64")]
pub(crate) static NEED_RESCHED: [core::sync::atomic::AtomicBool; MAX_HARTS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; MAX_HARTS];

/// Ask for a reschedule on the way out of this trap.
#[cfg(target_arch = "riscv64")]
pub(crate) fn request_resched(hart: usize) {
    if hart < MAX_HARTS {
        NEED_RESCHED[hart].store(true, core::sync::atomic::Ordering::Release);
    }
}

/// Called from `trap_entry.S` after the handler, with `sp` back on the
/// interrupted task's own stack.
///
/// Also the one place that reads the interrupt stack's magic word: a .bss
/// stack has no guard page, so without this an overflow would quietly eat the
/// slot below and surface as another hart's corruption.
#[cfg(target_arch = "riscv64")]
#[unsafe(no_mangle)]
pub extern "C" fn trap_resched(frame: &mut TrapFrame) {
    // Masked-window tracer: the interrupt path's window ends when this
    // returns towards the `sret` (every path below).
    #[cfg(feature = "lat-trace")]
    let _lat_exit = lat_trace::IrqExit(core::panic::Location::caller());
    // Lockdep (N1): no lock held when this returns to U-mode (also after a
    // switch away and back below).
    // QSBR (Kconfig RCU_QSBR, N4): see `riscv64_trap_handler`.
    let _rcu = azos_sync::qsbr::TrapBoundary::irq(|| (frame.sstatus as usize) & csr::SSTATUS_SPP == 0);
    let _ld = azos_sync::lockdep::UserReturn::arm(|| (frame.sstatus as usize) & csr::SSTATUS_SPP == 0);
    let hart = azos_arch::Cpu::hart_id(&azos_arch::ARCH) as usize;
    if !irq_stack_intact(hart) {
        crate::panic::halt_begin();
        azos_drv_sys::kerr!("[FATAL] Interrupt stack of hart {} overflowed its slot", hart);
        crate::panic::halt_report();
        // Same ending as a kernel page fault: the motors stop before the
        // machine does. A corrupted stack is not a state to keep driving in.
        #[cfg(feature = "domain-robot")]
        azos_robot::motor_cmd_publish(0, 0);
        azos_arch::Boot::shutdown(&azos_arch::ARCH);
    }
    // U01-4 (audit, 2026-09-26): never call schedule() before sched::start()
    // has run on this hart. Early boot enables SIE_SEIE|SIE_SSIE long before
    // the timer is armed, so a cross-hart IPI landing on the boot hart in
    // that window reached schedule() with no current task — the shape of
    // the open current_cpu_id() anomaly. Mirrors entry::aarch64::SCHED_LIVE.
    if !crate::entry::riscv64::SCHED_LIVE.load(Ordering::Acquire) {
        return;
    }
    // Interrupt taken from U-mode (never a nested one): the two pieces of
    // task work that may switch away run here, on the task's own stack, not
    // in `handle_interrupt` on the interrupt stack (wave 13 integration). A
    // task parked from the interrupt stack resumes on frames the hart's next
    // interrupts have overwritten: an exit's hook that blocks, or a
    // thread-group leader's wait for its members (`group_exit`), did exactly
    // that, and the hart later returned through a formatted log line.
    if (frame.sstatus as usize) & csr::SSTATUS_SPP == 0 {
        // RFC-0055: a task told to stop (`SYS_TASK_KILL` force) that computes
        // without a syscall ends here, a safe point: it holds no kernel lock
        // and no console. One load when no forced stop is pending anywhere.
        if azos_sched::scheduler::forced_stop_pending() {
            azos_sched::scheduler::exit_if_forced();
        }
        // Wave 13: a Linux task computing without a syscall takes its signal
        // here (the same safe point).
        if azos_limits::LINUX_ABI && azos_sched::scheduler::signal::work_pending() {
            super::exception::signal_return(frame, false);
        }
    }
    if hart < MAX_HARTS
        && NEED_RESCHED[hart].swap(false, core::sync::atomic::Ordering::AcqRel)
    {
        azos_sched::schedule();
    }
}


/// Periodic dump of the scheduler's no-switch counters, from the timer ISR.
///
/// **WHY from the ISR and not from `ipc_census_task`.** The census printer is
/// a task, and the failure being investigated is precisely "a task that never
/// gets dispatched" — on `-smp 1` the autorun ELF never runs, so assuming the
/// census task runs is assuming the thing under test. The timer interrupt
/// fires regardless of what the scheduler decides, which is the whole point.
// riscv64-only: its one call site is inside `handle_interrupt_inner`, which
// stays riscv64-gated (native `TrapFrame` trap dispatch, no aarch64
// counterpart in this file) — observed via an aarch64 "never used" warning
// before this gate was restored (kernel-main-merge task).
#[cfg(target_arch = "riscv64")]
#[cfg(feature = "ipc-census")]
fn dump_sched_counters() {
    use core::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    // 100 Hz tick, so every 300 ticks is ~3 s.
    if N.fetch_add(1, Ordering::Relaxed) % 300 != 0 { return; }
    let u = azos_sched::unswitched::read();
    let b = azos_sched::unswitched::block_split();
    let c = azos_sched::unswitched::call_split();
    kprintln!("[SCHED-DBG] do_schedule calls={} switches={} | no-switch BLOCKED aps={} q={} self={} / Running aps={} q={} self={} | block skipped={} slept={}",
        c.0, c.1, u.0, u.1, u.2, u.3, u.4, u.5, b.0, b.1);
    let mut top = [(0u32, 0u64, [0u8; 8], 0u8); 24];
    let n = azos_sched::top_runtime(&mut top);
    for e in top.iter().take(n) {
        let nm = core::str::from_utf8(&e.2).unwrap_or("?");
        kprintln!("[SCHED-DBG]   tid={} runtime={} state={} name={}", e.0, e.1, e.3, nm);
    }
    let (rdy, blk, run, per_cpu, runq, blkq, _r) = azos_sched::task_census();
    kprintln!("[SCHED-DBG]   census: ready={} blocked={} running={} per_cpu_queues={:?} ready_unqueued={} blocked_queued={} spin_gate_expired={} prio_guard_no_switch={}",
        rdy, blk, run, per_cpu, runq, blkq, azos_sched::spin_gate_expired(),
        azos_sched::prio_guard_no_switch());
    // RFC-0040 gap 2 stage 3. Printed here, and asserted by the gate, because
    // the hand-off changes LATENCY and nothing else: every functional IPC test
    // passes byte-identically whether the hint fires on every exchange or on
    // none of them. Without a count, a hand-off that silently stopped working
    // would leave the whole suite green.
    // Owner decision 102. Printed beside the hand-off counters for the same
    // reason: a budget that never refuses anything and a budget that is not
    // wired look identical from every functional test. `refused` must stay 0
    // on a healthy boot — a non-zero value means a legitimate program hit the
    // ceiling, and the gate says so instead of the program quietly failing to
    // allocate.
    let (peak_tid, peak_pages) = azos_sched::mm_peak_pages();
    kprintln!("[SCHED-DBG]   mem quota refused={} peak_live={} (tid={}) peak_ever={}",
        azos_sched::mm_quota_refusals(), peak_pages, peak_tid,
        azos_sched::mm_peak_global());
    // Wave 9: spawns and execs refused past their row's `instances`.
    kprintln!("[SCHED-DBG]   mem instances refused={}",
        azos_sched::scheduler::mm_instance_refusals());
    // Scan unit 3, the half that was left open: a COW break adds a frame to a
    // task's footprint and is deliberately NOT charged against its quota. The
    // reasoning is in `cow_table.rs`'s note on `note_cow_break` — three of the
    // four `handle_cow_fault` failure paths are the program's own bug, and the
    // store-fault arm kills the task on any `Err`, so charging-with-refusal
    // would add an indistinguishable fifth kill for an innocent task. The cost
    // is made LEGIBLE instead of chargeable.
    //
    // Visibility, not an assertion: no pass/fail regex keys on this line, and a
    // row that wanted to would read the NUMBER back rather than match the text
    // — a counter stuck at its initial value still prints a line.
    kprintln!("[SCHED-DBG]   mm cow breaks={}", azos_mm::cow::cow_break_frames());
    // Owner decision 2026-09-20 (scan unit 4). MUST stay 0: a non-zero count
    // means `fast_ipc_*` was entered from interrupt context (`in_isr_now`,
    // which reads `isr_depth`, NOT the interrupt-enable bit — so it keeps
    // meaning the same thing now that syscalls run with interrupts on, O3.1)
    // — which is the precondition for a same-hart deadlock on `FAST_IPC`. The
    // lock is deliberately NOT irqsave (that would mask interrupts across a
    // 64-slot scan on the hottest path); this is the detector that replaces it.
    kprintln!("[SCHED-DBG]   fast-ipc irq-ctx={}",
        azos_ipc::fast_ipc_irq_ctx_violations());
    // How many fast-IPC hand-offs switched straight to the woken
    // task (`scheduler::ipc_wake_then_block`) instead of through the run
    // queue. Evidence the path fires on a census kernel; not asserted.
    kprintln!("[SCHED-DBG]   fast-ipc direct={} unsaved-declined={}",
        azos_sched::scheduler::ipc_direct_switches(),
        azos_sched::scheduler::ipc_direct_unsaved());
    // Kernel output deferred behind a ring-3 console owner (wave 9): the
    // buffer's high-water mark against `uart::DEFER_BYTES`, and lines dropped
    // for want of room. Not asserted here; a drop prints its own
    // `[CONSOLE] dropped` line, which every gate row fails on.
    {
        let (hwm, dropped, deferred) = azos_drv_sys::uart::console_defer_stats();
        kprintln!("[SCHED-DBG]   console defer hwm={}/{} dropped_lines={} deferred_bytes={}",
            hwm, azos_drv_sys::uart::DEFER_BYTES, dropped, deferred);
    }
    // `sys_fork_impl` collapses six distinct refusal reasons to the same
    // wire `-1` (ABI-frozen; see `process.rs`'s own note on why it stays).
    // This is the coarse, periodic reader; `note_fork_refusal`'s own
    // one-shot `[FORK] refusal site first hit: ...` line is what reaches
    // aarch64, which has no counterpart to this riscv64+ipc-census dump.
    let fr = azos_sched::process::fork_refusal_counts();
    kprintln!("[SCHED-DBG]   fork refusals: kernel-task={} cow-failed={} kernel-slot-collision={} pool-exhausted={} tid-lookup-miss={} fork-ctx-identity-miss={} mem-locked={} mem-budget={}",
        fr[0], fr[1], fr[2], fr[3], fr[4], fr[5], fr[6], fr[7]);

    // K-C29 preemption audit. The counters live in TWO crates and reading only
    // the scheduler side hides the two that matter most: `underflow` says a
    // task exited holding a lock, `hart_oor` says a hart has no slot and is
    // silently running unprotected. Every one of these must read 0 until
    // `SpinLockGuard` carries a guard; `deferred` becoming non-zero is how we
    // will know the mechanism is live rather than merely compiled.
    let (defd, fired, y_at, b_at, e_at, s_at, off) = azos_sched::preempt_audit::read();
    let (underflow, hart_oor) = azos_sync::preempt::audit_counters();
    kprintln!("[SCHED-DBG]   preempt: deferred={} fired={} yield_atomic={} block_atomic={} exit_atomic={} switch_atomic={} underflow={} hart_oor={} last_block=tid:{} depth:{} reason:{}",
        defd, fired, y_at, b_at, e_at, s_at, underflow, hart_oor,
        off & 0xFFFF, (off >> 16) & 0xFF, off >> 24);
    // Ground truth for the `queued` claim. Everything else here trusts that
    // flag — `ready_unqueued` is literally `Ready && !queued` — so a task
    // holding a claim on a ring entry that does not exist reads as healthy in
    // every other line of this dump while never being scheduled again.
    let (cne, enc, dup, persistent) = azos_sched::ring_claim_audit();
    if cne != 0 || enc != 0 || dup != 0 {
        kprintln!("[SCHED-DBG]   rings: claim_no_entry={} entry_no_claim={} duplicates={} persistent={}",
            cne, enc, dup, persistent);
    }
    let mut ru = [(0u32, 0u32, 0u32, [0u8; 8], 0u8); 12];
    let k = azos_sched::ready_unqueued_ids(&mut ru);
    for e in ru.iter().take(k) {
        let nm = core::str::from_utf8(&e.3).unwrap_or("?");
        kprintln!("[SCHED-DBG]   READY-UNQUEUED tid={} prio={} home={} name={} site={} hart={}",
            e.0, e.1, e.2, nm, e.4 & 0x0F, e.4 >> 4);
    }
    let mut who = [(0u32, 0u32, [0u8; 8]); 5];
    let m = azos_sched::top_sched_callers(&mut who);
    for e in who.iter().take(m) {
        let nm = core::str::from_utf8(&e.2).unwrap_or("?");
        kprintln!("[SCHED-DBG]   ASKS-SCHED tid={} times={} name={}", e.0, e.1, nm);
    }
}

/// Handle asynchronous interrupts.
#[cfg(target_arch = "riscv64")]
pub(crate) fn handle_interrupt(_frame: &mut TrapFrame, cause: usize) {
    // Owner decision 2026-09-20 (scan unit 4) — mark interrupt context.
    //
    // Only this function knows it is an interrupt and not an exception:
    // hardware clears `sstatus.SIE` for both, so nothing downstream can tell
    // them apart from the CSR. `azos_ipc` reads this to notice a lock
    // taken from an ISR, which is the precondition for a same-hart deadlock on
    // `FAST_IPC` — deliberately detected rather than masked against, because
    // masking would cost interrupt latency on the hottest path in the system.
    //
    // The `exit` at every return is what keeps this honest, hence the single
    // wrapped body below rather than a bare `enter` here.
    let hart_for_isr = azos_arch::Cpu::hart_id(&azos_arch::ARCH) as usize;
    azos_sync::isr_depth::enter(hart_for_isr);
    // Wave 15 (TRACE): the irq class, around the whole dispatch; the id is
    // the `scause` interrupt code (5 timer, 9 external, 1 software).
    azos_trace::irq_entry(cause as u32);
    handle_interrupt_inner(_frame, cause);
    azos_trace::irq_exit(cause as u32);
    azos_sync::isr_depth::exit(hart_for_isr);
    // The forced stop and the Linux signal taken at an interrupt from U-mode
    // are NOT handled here: this runs on the hart's interrupt stack, and both
    // can end in a context switch that parks the task (an exit that blocks,
    // a thread-group leader waiting for its members). See `trap_resched`.
}

#[cfg(target_arch = "riscv64")]
fn handle_interrupt_inner(_frame: &mut TrapFrame, cause: usize) {
    #[cfg(feature = "ipc-census")]
    dump_sched_counters();
    match cause {
        INT_TIMER_S => {
            #[cfg(feature = "console-splice-smoke")]
            console_splice_isr_print();
            // F16.2: measure timer ISR handler latency
            let _isr_start = azos_drv_sys::wcet::wcet_begin();
            // F16.4: record jitter between successive timer ISR fires
            azos_drv_sys::wcet::jitter_record(azos_drv_sys::wcet::JITTER_TIMER_ISR);

            // E2E-WCET diagnostic: probe which sub-step of the ISR is
            // responsible for the multi-hundred-ms ISR wall times seen
            // under E2E load. Diagnostic builds only (`ipc-census`): under
            // plain `qemu` it put two `now()` reads, a multiply and a
            // divide around five calls of every tick, about 70
            // instructions on the interrupt-to-switch path the latency
            // rows measure (w14 RTMAX).
            #[cfg(feature = "ipc-census")]
            macro_rules! probe {
                ($label:literal, $body:expr) => {{
                    let t0 = azos_drv_sys::timebase::now();
                    let r = $body;
                    let elapsed_us = (azos_drv_sys::timebase::now()
                        .wrapping_sub(t0))
                        * 1_000_000 / azos_drv_sys::timebase::TIMER_FREQ;
                    if elapsed_us > 1_000 {
                        // Only print >1 ms so we don't flood the log.
                        kprintln!(
                            "[ISR-WCET] {} took {} µs",
                            $label, elapsed_us
                        );
                    }
                    r
                }};
            }
            #[cfg(not(feature = "ipc-census"))]
            macro_rules! probe {
                ($label:literal, $body:expr) => {{ let _ = $label; $body }};
            }

            let _ticks = azos_actuation::watchdog::tick();
            #[cfg(not(feature = "no-mmu"))]
            let ticks = _ticks;

            // Panicked-hart halt, then the K-A1 WDT feed (crates/core/actuation/src/watchdog.rs).
            azos_actuation::watchdog::halt_if_panicked();
            azos_actuation::watchdog::feed_from_timer_tick();

            // AQ0: Wake tasks whose timer deadline has expired.
            let now = azos_drv_sys::timebase::now();

            // M01: Update vDSO timing page (no ecall needed from user-space).
            #[cfg(not(feature = "no-mmu"))]
            {
                let uptime_ms = now / (azos_drv_sys::timebase::TIMER_FREQ / 1000);
                probe!("vdso_update", azos_mm::vdso::vdso_update(ticks, uptime_ms));
                // Wave 6: the running task's own vDSO page, if it mapped one.
                probe!("vdso_task_tick", azos_syscall::vdso_notify::vdso_task_tick(now));
            }
            probe!("wake_expired_timers", azos_sched::wake_expired_timers(now));
            // K-C25: deliver wakes stamped onto a task that then parked
            // (Blocked + WAKE_STAMP + context saved) — one-shot wakes have no
            // second chance, so the tick is their consumer of last resort.
            // See `sched_word::reap_orphaned_stamp` for the measured wedge.
            probe!("reap_stamped_sleepers", azos_sched::reap_stamped_sleepers());

            // M04: Expire leases whose deadline has passed.
            //
            // `iter().take(n)`, NOT `&expired[..n]`: `n` crosses an opaque
            // crate boundary (`lto = false`), so LLVM cannot discharge the
            // slice-range check and would emit a panic path — inside the
            // timer ISR, under `panic = "abort"`.
            probe!("lease_tick", {
                let mut expired = [0u32; azos_ipc::MAX_LEASES];
                let n = azos_ipc::lease_tick(now, &mut expired);
                for &lessor_tid in expired.iter().take(n) {
                    // Wake a lessor blocked in lease_wait_return (WaitQueue)
                    // so it observes the Expired state and undoes any
                    // inherited priority boost (RFC-0031 — no lost restore on
                    // expiry). That is the only wait a lessor has: no lease
                    // path blocks on `FastIpcServer`, and a
                    // `wake_fast_ipc_server(lessor)` here would dispatch the
                    // lessor if it were blocked as a fast-IPC server.
                    azos_sched::wq_wake_by_tid(lessor_tid);
                }
                // Wave 11 (LEASE3): the mappings of the leases that just
                // expired are removed by the lease worker, from task context,
                // whatever their lessors do.
                if n != 0 {
                    crate::tasks::wake_lease_worker();
                }
            });

            // M03: Schedule next timer at the nearest deadline (tickless).
            // Falls back to periodic tick if no tasks are sleeping on a timer.
            let hart = azos_arch::Cpu::hart_id(&azos_arch::ARCH);
            azos_drv_sys::timebase::set_next_tick_smart(
                hart as u32,
                azos_sched::nearest_timer_deadline(),
            );

            // F16.1: record timer ISR execution time BEFORE schedule().
            // schedule() may context-switch us out and back later — measuring
            // after it includes wall time of unrelated tasks and reports
            // bogus "1.2 second ISRs". The ISR's own work is the only
            // meaningful WCET data point here.
            azos_drv_sys::wcet::wcet_end(
                azos_drv_sys::wcet::WCET_TIMER_ISR, _isr_start);

            // Let the scheduler preempt if the current task's time slice expired.
            // `hart` is this hart's id, read above for set_next_tick_smart.
            irq_stack_probe(hart as usize);
            request_resched(hart as usize);
        }
        INT_EXTERNAL_S => {
            {
                let hart = azos_arch::Cpu::hart_id(&azos_arch::ARCH);
                let irq = azos_drv_irqchip::irqchip::claim(hart as u32);
                if irq != 0 {
                    // A line a ring-3 driver bound is delivered
                    // mask-until-ACK (wave 9 IRQ4, `azos_drv_irqchip::
                    // user_irq`): masked BEFORE the completion below, so a
                    // level device the driver has not quietened yet is not
                    // taken again on this handler's return; its
                    // `SYS_DRV_IRQ_ACK` unmasks it. The kernel's own lines
                    // (UART, virtio MSI) are never ring-3 owned.
                    let user = azos_drv_irqchip::user_irq::owned(irq);
                    if user {
                        #[cfg(not(feature = "irq-mask-canary"))]
                        azos_drv_irqchip::user_irq::mask(irq);
                        // Which hart took it (wave 10 IRQ5): the first ACK
                        // after a bind reports it.
                        azos_drv_irqchip::user_irq::note_taken(irq, hart as u32);
                        // Probe (wave 10 IRQ5 item 3): re-initialise this
                        // hart's interrupt controller while the line is held
                        // masked. `plic::init` must not rewrite the global
                        // priorities again, or captest's "line held masked
                        // until ACK" check fails.
                        #[cfg(feature = "irq-reinit-probe")]
                        azos_drv_irqchip::irqchip::init(hart as u32);
                    } else if irq == azos_drv_sys::uart::UART_IRQ {
                        // RFC-0055 S1: a reader parked on console input (the
                        // user shell's `SYS_CONSOLE_WAIT`, the recovery
                        // console's `readline`) left its TID; wake it the way
                        // aarch64's PL011 arm does — a TID wake of a `Timer`
                        // sleeper, which stamps a task not yet blocked.
                        if azos_drv_sys::uart::irq_handler() {
                            // Wave 13: `^C` on a console lent to a Linux job
                            // is SIGINT to that job (lock-free posts).
                            if azos_drv_sys::uart::take_intr() {
                                azos_syscall::linux::console_signal(2);
                            }
                            let tid = azos_drv_sys::uart::rx_waiter_take();
                            if tid != 0 && azos_sched::scheduler::wake_task_by_tid(
                                tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)))
                            {
                                request_resched(hart as usize);
                            }
                        }
                    } else if let Some(woke) = azos_drv_virtio::virtio::blk::irq(irq) {
                        // Wave 15: a disk request completed; its waiter
                        // sleeps until this wake (`boot::blk_irq`).
                        if woke { request_resched(hart as usize); }
                    } else if azos_drv_virtio::virtio::net::msi_irq(irq) {
                        if net_msi_wake() {
                            request_resched(hart as usize);
                        }
                    } else if azos_drv_virtio::virtio::net::mmio_irq(irq) {
                        // The virtio-mmio NIC's PLIC/APLIC source (Kconfig
                        // NET_RX_IRQ): acknowledged at the device, RX gate
                        // open; wake the poll task like an RX MSI.
                        if net_msi_wake() {
                            request_resched(hart as usize);
                        }
                    }

                    // F00.3: Dispatch to userspace IRQ bindings (ports, a
                    // wake-task binding's pending bit and TID wake) BEFORE
                    // the sweep: a waiter woken by TID there must not still
                    // be `Blocked` when the sweep runs (`irq_dispatch`).
                    azos_ipc::irq_dispatch(irq);

                    // AQ0: Wake tasks blocked on this IRQ.
                    azos_sched::wake_by_irq(irq);

                    azos_drv_irqchip::irqchip::complete(hart as u32, irq);
                    if user {
                        request_resched(hart as usize);
                    }
                }
            }
        }
        INT_SOFTWARE_S => {
            // IPI received. Today the only sender is (K-C15)
            // `cpu_enqueue_locked`, ringing a hart that has just been given a
            // ready task.
            //
            // **The TLB shootdown does not arrive here.** It exists since wave 8
            // (`crates/core/arch-riscv64/src/tlb.rs`) and its remote half is SBI
            // `remote_sfence_vma`: OpenSBI runs the `sfence.vma` on the target
            // hart in M-mode and waits for it, so this S-mode arm never sees a
            // shootdown. This arm used to run `csr::sfence_vma()`
            // unconditionally, for a shootdown IPI that nothing ever sent —
            // `send_ipi` had zero callers anywhere until K-C15 added the wake
            // doorbell below, so the flush was dead code guarding a message
            // that never arrived.
            //
            // Leaving it in place once the doorbell exists is not conservative,
            // it is expensive: it puts a full `sfence.vma zero, zero` on the
            // path of *every* cross-CPU wake. Measured under QEMU TCG — where a
            // global flush discards the whole softMMU TLB — it dominated the
            // very latency the doorbell was added to remove.
            //
            // Do NOT restore the flush here. A future S-mode shootdown IPI
            // (instead of SBI) would need a per-hart reason flag and a flush
            // only when that bit is set; otherwise every wake pays for it.
            // Clear S-mode software interrupt pending (SIP.SSIP = bit 1)
            // BEFORE rescheduling: schedule() may context-switch away and not
            // return here for a long time, and leaving SSIP set would re-enter
            // this arm immediately on the way out.
            csr::clear_sip_ssip();
            // The panic handler's stop IPI (Kconfig PANIC_QUIESCE) is this
            // same doorbell: once the kernel has panicked, park here. One
            // load otherwise.
            azos_actuation::watchdog::halt_if_panicked();
            #[cfg(feature = "ipc-census")]
            azos_sched::wakelat_ipi_recv();
            // K-C15: the whole point of the doorbell. Without this the hart
            // wakes from `wfi()`, finds nothing has asked it to do anything,
            // and goes straight back to sleep with a runnable task sitting in
            // its own queue.
            // `SCHED_REMOTE_WAKE_DEFER`: queue the wakes another hart left
            // for this one (its try of our queue lock failed). One load when
            // there are none.
            azos_sched::scheduler::drain_remote_wakes();
            request_resched(azos_arch::Cpu::hart_id(&azos_arch::ARCH) as usize);
        }
        _ => {
            // Avoid kprintln from ISR — it acquires the UART spinlock and
            // can block the ISR for ms when worker tasks hold the lock. The
            // irq class's entry record (`handle_interrupt`) names the cause.
        }
    }
}
