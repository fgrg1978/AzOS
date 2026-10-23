// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! riscv64 trap init and interrupt dispatch: `trap_init`, the timer/external/
//! software interrupt arms, and the deferred reschedule `trap_resched` that
//! `trap_entry.S` calls on the interrupt path. The interrupt-stack helpers
//! live here too: two of them run on that path, and keeping them in this
//! module keeps them inlinable into it.

use crate::*;
use crate::trap::Kernel;
#[cfg(feature = "hv")]
use azos_arch::trap::INT_GUEST_EXTERNAL_S;
use azos_arch::trap::INT_LCOF_S;

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

/// Initialize trap handling: set stvec, sscratch, scounteren (the clock only).
#[cfg(target_arch = "riscv64")]
pub(crate) fn trap_init() {
    // The boot CPU is logical CPU 0, so its vector is slot 0 of the per-hart
    // table (`trap_entry.S`): the entry point sits 4 bytes in, after the
    // slot's id word.
    unsafe extern "C" { static trap_hart_vectors: u8; }
    let trap_addr = (&raw const trap_hart_vectors) as usize + 4;
    assert!(trap_addr & 0x3 == 0, "trap vector not aligned");
    cpu::write_stvec(trap_addr);
    cpu::write_sscratch(0);
    // The clock for ring 3; the cycle and instret bits follow the PMU probe
    // (`azos_arch::pmu::start_this_cpu`, Kconfig PMU_USER), not a constant.
    cpu::write_scounteren(azos_arch::pmu::SCOUNTEREN_BOOT);
    kprintln!("[TRAP] Trap vector: {:#x}", cpu::read_stvec());
}

/// Called from `trap_entry.S` after the handler, with `sp` back on the
/// interrupted task's own stack: spend the reschedule flag the interrupt
/// raised (`crate::trap::irq::resched_exit`).
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
    crate::trap::irq::resched_exit::<Kernel, TrapFrame, MAX_HARTS>(&crate::trap::RESCHED, frame);
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
    kprintln!("[SCHED-DBG] do_schedule calls={} switches={} | no-switch BLOCKED q={} self={} / Running q={} self={} | block skipped={} slept={}",
        c.0, c.1, u.0, u.1, u.2, u.3, b.0, b.1);
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
    // Printed here, and asserted by the gate, because
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

/// The handler of a line the kernel enabled for itself: the UART console,
/// a virtio device, an MSI vector. Run in the external-interrupt handler, or,
/// for a line the IRQ thread serves (Kconfig IRQ_THREADED), in that thread
/// ([`kernel_line_bottom_half`]); one body for both. `true` when a task was
/// made ready (the interrupt path then raises the reschedule flag).
fn kernel_line(irq: u32) -> bool {
    if irq == azos_drv_sys::uart::UART_IRQ {
        // A reader parked on console input (the user shell's
        // `LOG_CONSOLE_WAIT`, the recovery console's `readline`) is woken.
        Kernel::console_rx().1
    } else if let Some(woke) = azos_drv_gpio::gpio::gpio_edge_irq(irq) {
        // The physical kill switch's edge: acknowledged and masked at the
        // GPIO controller, its task woken to sample, latch and stop
        // (`azos_actuation::kill_switch`). Never threaded: the IRQ thread
        // would add a wake to the stop's latency.
        woke
    } else if let Some(woke) = azos_drv_virtio::virtio::blk::irq(irq) {
        // Wave 15: a disk request completed; its waiter sleeps until this
        // wake (`boot::blk_irq`).
        woke
    } else if let Some(woke) = {
        // An SD/eMMC host's completion (`boot::blk_irq::wire_mmc_irq`): the
        // events are harvested here and its waiter sleeps until this wake.
        #[cfg(feature = "vf2")]
        { azos_drv_block::dwmshc::irq(irq) }
        #[cfg(any(feature = "k1", feature = "mmc-flush-smoke"))]
        { azos_drv_block::mmc::irq(irq) }
        #[cfg(not(any(feature = "vf2", feature = "k1", feature = "mmc-flush-smoke")))]
        { None::<bool> }
    } {
        woke
    } else if let Some(woke) = {
        // Kconfig DRV_NVME: a completion MSI of the NVMe controller
        // (`boot::nvme`); its waiters sleep.
        #[cfg(feature = "nvme")]
        { azos_drv_block::nvme::msi_irq(irq) }
        #[cfg(not(feature = "nvme"))]
        { None::<bool> }
    } {
        woke
    } else if let Some(woke) = {
        // Kconfig DRV_AHCI: a completion MSI of the SATA host (`boot::ahci`).
        #[cfg(feature = "ahci")]
        { azos_drv_block::ahci::msi_irq(irq) }
        #[cfg(not(feature = "ahci"))]
        { None::<bool> }
    } {
        woke
    } else if let Some(pushed) = {
        #[cfg(feature = "virtio-input")]
        { azos_drv_virtio::virtio::input::irq(irq) }
        #[cfg(not(feature = "virtio-input"))]
        { None::<bool> }
    } {
        // A virtio-input device (`boot::input_irq`): keys queued as console
        // bytes wake the parked reader.
        #[cfg(feature = "virtio-input")]
        {
            pushed && crate::console_rx_wake()
        }
        #[cfg(not(feature = "virtio-input"))]
        {
            let _ = pushed;
            false
        }
    } else if let Some(woke) = {
        // Kconfig DRV_VIRTIO_SND: the sound device's virtio-mmio line or its
        // MSI vector (`boot::snd_irq`): the device pump is woken when a stream
        // is open.
        #[cfg(feature = "virtio-snd")]
        { crate::boot::snd_irq::line(irq).or_else(|| crate::boot::snd_irq::msi(irq)) }
        #[cfg(not(feature = "virtio-snd"))]
        { None::<bool> }
    } {
        woke
    } else if azos_drv_virtio::virtio::net::msi_irq(irq) {
        net_msi_wake()
    } else if azos_drv_net::net_device::pci_msi_irq(irq) {
        // Kconfig DRV_E1000E / DRV_IGC: an Intel NIC's MSI.
        net_msi_wake()
    } else if azos_drv_net::net_device::irq(irq) {
        // The NIC's PLIC/APLIC source (Kconfig NET_RX_IRQ): the virtio-mmio
        // NIC's, or the VisionFive 2's gmac0. Acknowledged at the device, RX
        // gate open; wake the poll task like an RX MSI.
        net_msi_wake()
    } else {
        false
    }
}

/// [`kernel_line`] as the IRQ thread runs it (Kconfig IRQ_THREADED): the line
/// was masked and completed by the interrupt handler, the thread acknowledges
/// it at the device here and unmasks it afterwards.
pub(crate) fn kernel_line_bottom_half(irq: u32) {
    let _ = kernel_line(irq);
}

/// Handle asynchronous interrupts: the generic bracket (QSBR boundary, ISR
/// depth) around the `scause` decode below. The ISR depth marks interrupt
/// context: hardware clears `sstatus.SIE` for exceptions too, so only here is
/// it known to be an interrupt, and `azos_ipc` reads it to notice a lock taken
/// from an ISR.
///
/// The forced stop and the Linux signal taken at an interrupt from U-mode are
/// NOT handled here: this runs on the hart's interrupt stack, and both can end
/// in a context switch that parks the task. See `trap_resched`.
#[cfg(target_arch = "riscv64")]
pub(crate) fn handle_interrupt(frame: &mut TrapFrame, cause: usize) {
    crate::trap::irq::arm::<Kernel, TrapFrame>(frame, |frame| {
        // Wave 15 (TRACE): the irq class, around the whole dispatch; the id is
        // the `scause` interrupt code (5 timer, 9 external, 1 software).
        azos_trace::irq_entry(cause as u32);
        handle_interrupt_inner(frame, cause);
        azos_trace::irq_exit(cause as u32);
    });
}

/// What the profiler (Kconfig `PROFILER`) samples of the interrupted code,
/// for the tick and the counter overflow alike.
#[cfg(target_arch = "riscv64")]
fn interrupted(frame: &TrapFrame) -> crate::prof::Interrupted {
    crate::prof::Interrupted {
        pc: frame.sepc as usize,
        fp: frame.regs[8] as usize,
        sp: frame.regs[2] as usize,
        user: (frame.sstatus as usize) & cpu::SSTATUS_SPP == 0,
    }
}

#[cfg(target_arch = "riscv64")]
fn handle_interrupt_inner(_frame: &mut TrapFrame, cause: usize) {
    #[cfg(feature = "ipc-census")]
    dump_sched_counters();
    match cause {
        INT_TIMER_S => {
            // The sampling profiler (Kconfig `PROFILER`): the interrupted code.
            crate::prof::on_tick(|| interrupted(_frame));
            #[cfg(feature = "console-splice-smoke")]
            console_splice_isr_print();
            // F16.2: measure timer ISR handler latency
            let _isr_start = azos_drv_sys::wcet::wcet_begin();
            // F16.4: record jitter between successive timer ISR fires
            azos_drv_sys::wcet::jitter_record(azos_drv_sys::wcet::JITTER_TIMER_ISR);

            // The work every ISA's tick shares: the watchdog trio, the vDSO
            // pages (no ecall needed from user-space), the timers whose
            // deadline expired and the wakes stamped onto a task that parked
            // (K-C25: one-shot wakes have no second chance). The sleepers'
            // sweep is the long step of an overloaded tick; `ipc-census`
            // builds name it when it takes over a millisecond (E2E-WCET).
            let now = azos_drv_sys::timebase::now();
            #[cfg(feature = "ipc-census")]
            let t0 = azos_drv_sys::timebase::now();
            crate::trap::irq::tick_work::<Kernel, TrapFrame>(
                now, None, Some(now / (azos_drv_sys::timebase::TIMER_FREQ / 1000)));
            #[cfg(feature = "ipc-census")]
            {
                let us = azos_drv_sys::timebase::now().wrapping_sub(t0) * 1_000_000
                    / azos_drv_sys::timebase::TIMER_FREQ;
                if us > 1_000 {
                    kprintln!("[ISR-WCET] tick_work took {} us", us);
                }
            }

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
            crate::trap::RESCHED.request(hart as usize);
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
                    // `DEVICE_IRQ_ACK` unmasks it. A kernel line the IRQ
                    // thread serves (Kconfig IRQ_THREADED,
                    // `irq_thread::deferred`) is delivered the same way, and
                    // its thread ACKs it after the handler ran there.
                    let user = azos_drv_irqchip::user_irq::owned(irq);
                    let threaded = !user && crate::irq_thread::deferred(irq);
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
                    } else if azos_drv_irqchip::irqchip::user_msi_owned(irq) {
                        // An IMSIC identity a ring-3 handler holds
                        // (`DEVICE_IRQ_BIND` on an `msi.<k>` slot): nothing
                        // to mask or acknowledge; the event is queued on its
                        // port, or dropped while the handler is out of
                        // budget.
                        if azos_ipc::irq_msi_dispatch(irq) {
                            crate::trap::RESCHED.request(hart as usize);
                        }
                    } else if threaded {
                        azos_drv_irqchip::user_irq::mask(irq);
                    } else if kernel_line(irq) {
                        crate::trap::RESCHED.request(hart as usize);
                    }

                    // Dispatch to a handler's port (`irq_dispatch`: the event
                    // queued, its waiter woken by TID).
                    azos_ipc::irq_dispatch(irq);

                    azos_drv_irqchip::irqchip::complete(hart as u32, irq);
                    if user || threaded {
                        crate::trap::RESCHED.request(hart as usize);
                    }
                }
            }
        }
        // Sscofpmf's counter overflow (LCOFI): the profiler's sampling counter
        // (Kconfig PROFILER_PMU), acknowledged and re-armed by `on_overflow`.
        INT_LCOF_S => crate::prof::on_overflow(|| interrupted(_frame)),
        // A guest file a waiting vCPU armed has an identity pending: disarm
        // it and wake the thread (it enters the guest, whose `VSEIP` the
        // hardware raises from the file).
        #[cfg(feature = "hv")]
        INT_GUEST_EXTERNAL_S => {
            crate::entry::riscv64::ext::hv::guest_external(azos_arch::Cpu::hart_id(&azos_arch::ARCH) as usize);
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
            // shootdown. This arm used to run `cpu::sfence_vma()`
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
            cpu::clear_sip_ssip();
            #[cfg(feature = "ipc-census")]
            azos_sched::wakelat_ipi_recv();
            // K-C15: the whole point of the doorbell. Without this the hart
            // wakes from `wfi()`, finds nothing has asked it to do anything,
            // and goes straight back to sleep with a runnable task sitting in
            // its own queue. (The panic handler's stop IPI is this same
            // doorbell.)
            Kernel::ipi_work();
            crate::trap::RESCHED.request(azos_arch::Cpu::hart_id(&azos_arch::ARCH) as usize);
        }
        _ => {
            // No kprintln here: it takes the console lock, which a task may
            // hold for a whole line. The irq class's entry record
            // (`handle_interrupt`) names the cause. The ISR prints only the
            // one-shot `irq_stack_probe` line and, in diagnostic builds
            // (`ipc-census`), the census dump and `[ISR-WCET]` lines, whose
            // masked windows those builds accept.
        }
    }
}
