// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! riscv64 synchronous exceptions: the syscall (`ecall`) arm, page faults
//! (COW, demand paging, guards) and the fatal-fault post-mortem.

use azos_arch::Cpu as _;
use crate::entry::TrapContext as _;
use crate::*;
// Not from the crate root: there `trap` names this module tree.
use azos_arch::trap;

/// Post-mortem line naming the null guard when the faulting VA is inside it.
///
/// Only ever called from a fault that is already fatal for the task, so the
/// UART cost is irrelevant here. It exists because "Store page fault at 0x8"
/// on its own does not tell the reader that the kernel *refused* to fix it:
/// without this line the guard looks like an ordinary unmapped page, and the
/// next person to debug a null dereference re-derives why demand paging did
/// not kick in. See `azos_mm::vmm::USER_GUARD_LIMIT`.
#[inline]
#[cfg(target_arch = "riscv64")]
fn page_fault_note_guard(stval: usize, show: bool) {
    if show && azos_mm::vmm::in_null_guard(stval) {
        azos_drv_sys::kwarn!("  null guard: VA < {:#x} is never mapped (null pointer dereference)",
            azos_mm::vmm::USER_GUARD_LIMIT);
    }
}

/// Post-mortem line with the faults this system resolved *silently* before
/// this one. This is where the counters bumped on the fast path are consulted
/// — the page-fault arm no longer prints anything for a fault it fixes, so
/// this line is what preserves the "how much COW traffic was there" signal
/// that the old per-fault banner used to carry, at zero cost per fault.
#[inline]
#[cfg(target_arch = "riscv64")]
fn page_fault_note_resolved(show: bool) {
    if !show { return; }
    let (cow, demand) = azos_mm::vmm::faults_resolved();
    azos_drv_sys::kwarn!("  resolved so far: {} COW, {} demand", cow, demand);
}

// F4 (wave 3) — O3.1 nested-trap probe. Reserved syscall number the ecall
// arm intercepts BEFORE normal dispatch (see `handle_exception` above): well
// past the real syscall table (`crates/core/abi/src/syscall_nr.rs`), so it can
// never collide with a real syscall a build ships.
//
// Spins ~50 ms reading `time` (`now_ticks`) with interrupts already enabled
// by THIS call's own `ARCH.enable_all()` (skipped for this arm — the probe
// enables inline below so the deadline is measured from the same point a
// real syscall's enable would run). Meant for `-smp 1`: the timer fires
// locally, no cross-hart placement to account for. Prints `TICK_COUNT`
// (`azos_actuation::watchdog::ticks()`) before and after — the tick
// must have advanced, proving the timer actually fired and returned control
// here rather than crashing into another task's stack. Returns 0 (no SATP
// switch) unconditionally; a return that reaches this line is a pass by
// definition, since a wrong-stack corruption from the bug this proves kills
// the boot before any return value is observed.
#[cfg(all(target_arch = "riscv64", feature = "irq-in-syscall-probe"))]
pub(crate) const PROBE_IRQ_IN_SYSCALL_NR: usize = 4_000_000;

#[cfg(all(target_arch = "riscv64", feature = "irq-in-syscall-probe"))]
pub(crate) fn probe_irq_in_syscall() -> usize {
    azos_arch::ARCH.enable_all();
    let tick_before = azos_actuation::watchdog::ticks();
    let hz = azos_drv_sys::timebase::TIMER_FREQ;
    let deadline = azos_arch::ARCH.now_ticks() + hz / 20; // ~50 ms
    while azos_arch::ARCH.now_ticks() < deadline {}
    let tick_after = azos_actuation::watchdog::ticks();
    kprintln!("[IRQ-PROBE] tick_before={} tick_after={} advanced={}",
        tick_before, tick_after, tick_after > tick_before);
    0
}

/// The syscall entry record (wave 15): `[nr, tid, a0, a1]` from the frame.
#[cfg(target_arch = "riscv64")]
#[inline(never)]
fn trace_sys_enter(frame: &TrapFrame) {
    azos_trace::raw::sys_enter(frame.regs[17] as u32, azos_sched::current_task_tid(), frame.regs[10] as u64, frame.regs[11] as u64);
}

/// The syscall exit record (wave 15): `[nr, tid, ret]` from the frame.
#[cfg(target_arch = "riscv64")]
#[inline(never)]
fn trace_sys_exit(frame: &TrapFrame) {
    azos_trace::raw::sys_exit(frame.regs[17] as u32, azos_sched::current_task_tid(), frame.regs[10] as i64);
}

/// The `ecall` path of [`handle_exception`] (U-mode and S-mode). Entered
/// straight from `riscv64_trap_handler` for a U-mode `ecall` (SYSFLOOR), so a
/// syscall no longer pays `handle_exception`'s cause decode and the frame its
/// page-fault arms need. `txn_try_rollback` only claims misaligned-access
/// causes, so running this before it changes nothing for an `ecall`.
#[cfg(target_arch = "riscv64")]
#[inline(never)]
pub(crate) fn handle_ecall(frame: &mut TrapFrame) -> usize {
    // Wave 15 (TRACE): the syscall class's entry tracepoint, FIRST and out
    // of line, reading everything from the frame: then nothing but `frame`
    // is live across its call, and the function keeps its register shape
    // (no extra callee-saved register to save on every syscall). Compiled
    // out (no instruction) unless Kconfig `KTRACE` and `KTRACE_CLASS_SYSCALL`;
    // compiled in, a mask test while the class is off.
    if azos_trace::syscall_on() {
        trace_sys_enter(frame);
    }
    let num = frame.syscall_number(); // a7
    azos_sched::swcensus::ecall_enter();

    // O3.1 (owner decision, 2026-09-26): syscalls run with interrupts
    // enabled once the frame is saved (Linux model). LANDED (F4, wave
    // 3) after the entry-path fix this decision was blocked on: with
    // `ARCH.enable_all()` here and the OLD `trap_return`, `ipctest`
    // (-smp 4) hit 2 kernel panics + 1 page fault in 3 boots, with
    // USER register values (ipctest's FORK_CANARY 0x5AFEC0DE, its shm
    // VA 0x60000000) turning up as return addresses on OTHER tasks'
    // kernel stacks (net-poll, flight-ctrl) at a constant +
    // TRAP_FRAME_SIZE offset.
    //
    // ROOT CAUSE (kernel/src/entry/riscv64/asm/trap_entry.S,
    // `trap_return`): the old code wrote `sscratch` (U-mode path) or
    // `sepc` (both paths) *before* restoring the frame's own
    // `sstatus` — so a live timer, still enabled from THIS call,
    // could trap in the gap. It would read the just-written
    // `sscratch` as a valid kernel SP, allocate its own frame at
    // `sscratch - TRAP_FRAME_SIZE` (the syscall's own frame, not yet
    // restored) and record the wrong resume SP
    // (`save_smode_sp`'s `sp + TRAP_FRAME_SIZE`, off by
    // `TRAP_FRAME_SIZE` because it read `sp` post-`csrrw`, not the
    // true pre-trap value that went into `sscratch`) — so the
    // interrupted syscall resumed one frame above the top of its own
    // `TASK_STACKS` slot, into the bottom of the next task's. FIX:
    // `trap_return` now writes the frame's `sstatus` FIRST, before
    // `sscratch` or `sepc`, closing SIE (when the frame says so)
    // before either becomes observable to a nested trap — same
    // ordering `process.rs`'s `sret_to_user`/`sret_to_user_forked`
    // already use on the way in, applied on the way out. Zero added
    // instructions (the write moved, not duplicated).
    //
    // Asm-only regression (enable_all still off, F4's private build):
    // `ipctest` x5 / reflex x3 clean at -smp 4 with the new
    // `trap_return` ordering. `irq-in-syscall-probe` below, and this
    // enable, need a boot with THIS diff applied to prove the rest —
    // coordinator, see F4-REPORT.md.
    #[cfg(feature = "irq-in-syscall-probe")]
    if num == PROBE_IRQ_IN_SYSCALL_NR {
        return probe_irq_in_syscall();
    }
    azos_arch::ARCH.enable_all();

    // Snapshot before dispatch: `frame.regs[10]` is overwritten with the
    // return value below, and a forked child must inherit the register
    // file as it was at the `ecall`.
    // **No register-file copy.**
    //
    // This used to read `let reg_snapshot: [u64; 32] =
    // core::array::from_fn(|i| frame.regs[i] as u64);` — a copy of all
    // 32 registers **on every syscall**: 64 memory accesses and 256
    // bytes of stack, paid by `getpid` exactly as by `fork`.
    //
    // It was pointless twice over. `RegVal` is already `u64`
    // (`crates/core/arch-riscv64/src/trap.rs`), so the `as u64` converted
    // nothing; and of the hundred-odd syscalls only **two** look at
    // this parameter: `SYS_FORK` and `SYS_FORK_COW`.
    //
    // **Why passing `&frame.regs` is safe**, which is what the comment
    // below feared: `set_task_fork_ctx` does `task.fork_regs = *regs`,
    // an **immediate** copy, inside the call; and the writes to
    // `frame.regs[10..15]` happen after `syscall_dispatch_out` has
    // returned. No arm can observe the already-modified frame, because
    // it is not modified yet. Verified by following the chain
    // sys_fork -> sys_fork_impl -> set_task_fork_ctx, not assumed.


    // K-A15: sepc/user_sp passed straight through as call parameters
    // (this trap frame's own values, hart-local) instead of via the
    // shared-global `set_ecall_context` this replaced — see the doc
    // on `syscall_dispatch` for why that mattered for SYS_FORK.
    // Extra return registers (fast-IPC payload delivery).
    //
    // **WHY an out-parameter and not `&mut frame.regs`.** The arms get
    // `&frame.regs` — a *shared* borrow, so no arm can write through
    // it, which is what keeps a forked child inheriting the register
    // file as it stood at the `ecall`. Arms that return more than `a0`
    // fill `out`, and the copy back happens here, after the borrow has
    // ended.
    // SYSFLOOR: the filter verdict and the three register-only calls
    // first (`syscall_entry_fast`); the argument list, the `SyscallOut`
    // and the copy-back below are built only for a call that needs them,
    // out of line in `ecall_dispatch`. The filter still runs first for
    // every number, exactly as inside `syscall_dispatch_out`.
    let result = match azos_syscall::syscall_entry_fast(num as u64) {
        azos_syscall::SyscallEntry::Done(r) => r,
        entry => ecall_dispatch(frame, num as u64, entry),
    };
    frame.set_syscall_return(result as usize); // a0
    // The exit tracepoint, as the entry one: the number and the result are
    // read back from the frame.
    if azos_trace::syscall_on() {
        trace_sys_exit(frame);
    }
    // Skip the `ecall`. Wrapping: an `ecall` at the top 4 bytes of the
    // address space cannot exist (no U-mode or kernel mapping is there), so
    // the overflow panic was two dead instructions on every syscall.
    frame.set_pc(frame.pc().wrapping_add(4));

    // K-C21: if THIS task ran exec_user() inside this ecall, consume
    // its own hand-off and switch to U-mode. Per-task, not the old
    // global slot — another hart finishing an unrelated syscall in
    // this window can no longer steal the context and SRET into an
    // address space that was never its own. The taker has already
    // installed the new satp and destroyed the replaced address
    // space (K-C22); the value returned here makes the SRET path
    // re-write the satp already in force, which is harmless.
    #[cfg(not(feature = "no-mmu"))]
    if let Some(ctx) = azos_sched::take_current_task_exec_ctx() {
        frame.sepc      = ctx.entry as _;
        frame.sstatus   = ctx.sstatus as _; // SPP=0, SPIE=1
        frame.regs[2]   = ctx.user_sp as _; // user SP
        return ctx.satp as usize;            // switch page table
    }
    // Wave 13: signal work (a Linux task's pending signal or
    // sigreturn) at this return to user mode. One load when there is
    // none anywhere; the work itself is out of line.
    if azos_limits::LINUX_ABI && azos_sched::scheduler::signal::work_pending() {
        signal_return(frame, true);
    }
    azos_sched::swcensus::ecall_exit();
    0
}

/// Everything a syscall that `syscall_entry_fast` did not answer needs: its
/// arguments, the out-parameter and the copy-back of the extra return
/// registers. Out of line so `handle_ecall` keeps the frame of the common
/// path.
#[cfg(target_arch = "riscv64")]
#[inline(never)]
fn ecall_dispatch(frame: &mut TrapFrame, num: u64, entry: azos_syscall::SyscallEntry) -> i64 {
    let mut out = azos_syscall::SyscallOut::new();
    let result = azos_syscall::syscall_dispatch_checked(
        entry, num,
        frame.regs[10] as u64, frame.regs[11] as u64, frame.regs[12] as u64,
        frame.regs[13] as u64, frame.regs[14] as u64, frame.regs[15] as u64,
        frame.sepc as u64, frame.regs[2] as u64,
        // K-C11: the parent's whole user register file. SYS_FORK is the
        // only consumer — the child has to resume the parent's code with
        // its callee-saved registers intact, not with whatever the kernel
        // task that dispatched it happened to leave behind.
        &frame.regs,
        &mut out,
    );
    // **WHY `written` is not decoration.** `a1..a6` are *argument*
    // registers, and every `libsys` wrapper passes them as `in("aN")` —
    // operands rustc is entitled to assume survive the call. Writing
    // them unconditionally would be UB in ring 3 across the whole tree,
    // so only the arms that opt in get copied back.
    //
    // Unrolled on purpose: `for i in 0..SYSCALL_OUT_REGS` trips
    // `needless_range_loop`, and warnings are failures in this project.
    //
    // `a6` (`regs[16]`) joined in RFC-0040 gap 2 stage 4: it carries
    // the handle a moved capability took in the RECEIVER's table, or
    // `NO_CAP_MOVED`. `a7` (`regs[17]`) is the syscall number and is
    // never written back.
    if out.written {
        frame.regs[11] = out.regs[0] as _; // a1 = caller TID
        frame.regs[12] = out.regs[1] as _; // a2..a5 = request words
        frame.regs[13] = out.regs[2] as _;
        frame.regs[14] = out.regs[3] as _;
        frame.regs[15] = out.regs[4] as _;
        frame.regs[16] = out.regs[5] as _; // a6 = moved capability
    }
    result
}

/// Handle synchronous exceptions.
///
/// Returns the SATP to switch to on SRET (0 = keep current page table).
///
/// Never inlined: its one caller, `riscv64_trap_handler`, is also the
/// U-mode `ecall` path (`handle_ecall`, SYSFLOOR). Inlined, this body's
/// register pressure moved into that frame and cost every syscall 22
/// instructions (vsbench `syscall-floor` 195 -> 217 ns/op under -icount),
/// and whether LLVM inlined it flipped on an unrelated edit elsewhere in
/// the kernel crate (wave 14, LOGLEVEL).
#[cfg(target_arch = "riscv64")]
#[inline(never)]
pub(crate) fn handle_exception(frame: &mut TrapFrame, cause: usize) -> usize {
    // I-13 (RFC-0029): transactional control-tick rollback. A recoverable
    // fault inside an armed tick restarts the control task at a safe-stop
    // instead of the fatal path below. Excludes ecall + page-fault causes
    // (txn_is_recoverable whitelist), so their handlers run unchanged.
    #[cfg(feature = "domain-robot")]
    if txn_try_rollback(frame, cause) {
        return 0;
    }
    match cause {
        // ── System calls (ecall from U-mode or S-mode) ────────────────────
        TRAP_ECALL_FROM_U | TRAP_ECALL_FROM_S => handle_ecall(frame),

        // ── Page faults: kill user task, fatal if from kernel ──────────
        TRAP_INSTR_PAGE_FAULT | TRAP_LOAD_PAGE_FAULT | TRAP_STORE_PAGE_FAULT => {
            let hart = azos_arch::ARCH.hart_id();
            // SPP bit: 0 = came from U-mode, 1 = came from S-mode.
            let from_user = (frame.sstatus as usize) & csr::SSTATUS_SPP == 0;

            // The fault class's tracepoint, on EVERY fault, resolved or not:
            // a lock-free per-CPU record, and what `trace_dump` replays on
            // the fatal path below (Kconfig `KTRACE_CLASS_FAULT`).
            if azos_trace::fault_on() {
                azos_trace::raw::page_fault(frame.stval as u64, cause as u32, azos_sched::current_task_tid());
            }

            // The banner used to be printed HERE, before COW and demand paging
            // were even attempted. Nearly every fault this kernel takes is a
            // COW break from `fork()` that resolves fine, so the log filled up
            // with blocks that read exactly like a fatal crash and were not:
            // in one 30 s `ipctest` run, 3 of 3 `[PAGE FAULT]` blocks were
            // successful COW breaks, and they cost two humans (and one agent)
            // a wrong diagnosis. It is also ~160 µs of UART-lock time per
            // 64 bytes under QEMU, paid on the hot fork path.
            //
            // So: resolve first, print only what could NOT be resolved. Do not
            // move these prints back up — the unresolved path below still
            // emits every field the old banner did, plus the resolved-fault
            // counters, so nothing is lost where it actually matters.
            if from_user {
                // AQ9: Try COW fault resolution first (store page fault only).
                #[cfg(not(feature = "no-mmu"))]
                if cause == TRAP_STORE_PAGE_FAULT {
                    let user_pt = azos_sched::current_user_pt();
                    if user_pt != 0 {
                        match azos_mm::vmm::handle_cow_fault(user_pt, frame.stval as usize) {
                            Ok(()) => {
                                azos_mm::vmm::note_cow_resolved();
                                return 0; // COW resolved, resume task — silently
                            }
                            // TELL THE INNOCENT CASE APART FROM THE GUILTY ONES.
                            //
                            // `handle_cow_fault` has four failure paths and
                            // three of them mean "this was never a COW fault":
                            // a null dereference (`in_null_guard`), an address
                            // that is not mapped at all (`vmm::walk`), and a
                            // write to a page that exists but is not
                            // copy-on-write — writing to `.rodata`, say
                            // (`NotMapped`). Killing the task is exactly right
                            // for those; it is what this whole arm is for.
                            //
                            // `OutOfMemory` is the one where the program did
                            // nothing wrong: it wrote to its own page, after
                            // its own `fork`, and the allocator was empty. It
                            // printed the same block as a null dereference,
                            // which sends whoever reads the log hunting a
                            // pointer bug that does not exist.
                            //
                            // The task still dies — a page fault is a trap,
                            // there is no return value to hand ring 3, and
                            // resuming without resolving it re-faults forever.
                            // This ABI has no signal or upcall to deliver the
                            // failure to. What changes is that the log stops
                            // lying about the cause.
                            Err(azos_common::error::KernelError::OutOfMemory) => {
                                azos_drv_sys::kerr!();
                                azos_drv_sys::kerr!("[PAGE FAULT] OUT OF MEMORY breaking copy-on-write \
                                           at {:#x} — the task did nothing wrong; the page \
                                           allocator is empty", frame.stval);
                                azos_drv_sys::kerr!("  task: {} (tid {})",
                                    azos_sched::current_task_name(),
                                    azos_sched::current_task_tid());
                                // Durable, like every other safety event: a
                                // console line is gone by the time anyone asks
                                // why a task vanished.
                                let _ = azos_actuation::logger::log_safety_violation_durable(
                                    azos_actuation::logger::SAFETY_COW_OOM,
                                    // action_code names the SITE: 0 = the
                                    // store-page-fault arm of the trap handler.
                                    0,
                                    frame.stval as u32,
                                );
                            }
                            Err(_) => {}
                        }
                    }
                }

                // AQ10: Try demand paging (load/store/instr fault on a demand-mapped page).
                // Both handlers refuse any VA under `vmm::USER_GUARD_LIMIT`,
                // so a null dereference can never be "resolved" into a mapped
                // zero page — it falls through to the kill below.
                #[cfg(not(feature = "no-mmu"))]
                {
                    let user_pt = azos_sched::current_user_pt();
                    if user_pt != 0 {
                        if azos_mm::vmm::handle_demand_fault(user_pt, frame.stval as usize).is_ok() {
                            azos_mm::vmm::note_demand_resolved();
                            return 0; // Page allocated on demand, resume — silently
                        }
                    }
                }

                // Neither COW nor demand paging — this one is real. Full
                // post-mortem, then kill the offending task.
                // The report is rate limited (`user_fault_report`); the kill,
                // its exit status and the lease record are not.
                let show = user_fault_report();
                if show {
                    azos_drv_sys::kwarn!();
                    azos_drv_sys::kwarn!("[PAGE FAULT] CPU {} — {} at {:#x}",
                        hart, trap::cause_str(cause), frame.stval);
                    azos_drv_sys::kwarn!("  sepc: {:#x}  task: {}", frame.sepc,
                        azos_sched::current_task_name());
                }
                page_fault_note_guard(frame.stval as usize, show);
                page_fault_note_resolved(show);
                page_fault_note_lease(frame.stval as usize, show);
                if show {
                    azos_drv_sys::kwarn!("[PAGE FAULT] Killing user task");
                }
                azos_sched::scheduler::task_exit_by_signal(azos_abi::exit_status::KILLED_SEGV);
                // task_exit() never returns — context_switch abandons this frame.
            } else {
                // S-mode (kernel) fault: this is a kernel bug. Nothing here is
                // recoverable, so this branch prints everything unconditionally.
                // First, so none of it is parked behind a ring-3 console owner
                // or spliced by another CPU's lines (`panic::halt_begin`).
                crate::panic::halt_begin();
                azos_drv_sys::kerr!();
                azos_drv_sys::kerr!("[PAGE FAULT] CPU {} — {} at {:#x}",
                    hart, trap::cause_str(cause), frame.stval);
                azos_drv_sys::kerr!("  sepc: {:#x}  task: {}", frame.sepc,
                    azos_sched::current_task_name());
                page_fault_note_guard(frame.stval as usize, true);
                page_fault_note_resolved(true);
                // Stop all motors, log diagnostics, shutdown system.
                azos_drv_sys::kerr!("[FATAL] Kernel page fault on CPU {} — initiating shutdown", hart);
                azos_drv_sys::kerr!("  regs[1] (ra):  {:#x}", frame.regs[1]);
                azos_drv_sys::kerr!("  regs[2] (sp):  {:#x}", frame.regs[2]);
                azos_drv_sys::kerr!("  regs[8] (s0):  {:#x}", frame.regs[8]);
                crate::panic::halt_report();
                // AQ8: Dump trace buffer before dying — last chance for debugging.
                azos_ipc::trace_dump(20);
                // Emergency motor stop to prevent runaway
                #[cfg(feature = "domain-robot")]
                azos_robot::motor_cmd_publish(0, 0);
                azos_arch::Boot::shutdown(&azos_arch::ARCH);
            }
        }

        // ── All other exceptions: fatal only if they came from S-mode ─────
        //
        // Illegal instruction (cause 2), `ebreak`, misaligned load/store and
        // the rest land here. This arm used to shut the board down
        // unconditionally, which made it strictly harsher than the page-fault
        // arm directly above for no defensible reason: a ring-3 task that
        // dereferences a null pointer merely dies, but a ring-3 task that
        // executes one bad opcode killed the whole robot.
        //
        // That is not a theoretical gap. An ELF whose entry point lands on
        // garbage inside a mapped RX page raises cause 2, NOT a page fault —
        // the page is mapped and executable, the bytes are just not
        // instructions — so it never reached the "kill the offending task"
        // path next door. On the autorun path that ELF is read from the FAT32
        // volume `msc_gadget.rs` also exports over USB mass storage, so a file
        // truncated by a yanked cable produced a guaranteed shutdown loop:
        // boot, exec, illegal instruction, shutdown, repeat — with no shell
        // ever reaching a prompt to replace the bad file.
        //
        // The privilege split is the fix: WHERE the trap came from is what
        // decides whether this is a kernel bug (unrecoverable) or just a bad
        // program (kill it and carry on).
        _ => {
            // RFC-0047 stage 3: a Linux task's first FP instruction (FS is
            // Off in its frame) gets it the F/D file and is retried.
            if cause == 2
                && (frame.sstatus as usize) & csr::SSTATUS_SPP == 0
                && azos_sched::fp::first_use(&mut frame.sstatus)
            {
                return 0;
            }
            let hart = azos_arch::ARCH.hart_id();
            // SPP bit: 0 = came from U-mode, 1 = came from S-mode. Exactly the
            // mechanism the page-fault arm uses — once we are inside the
            // handler, sstatus.SPP is the only trustworthy record of the
            // privilege level the trap interrupted.
            let from_user = (frame.sstatus as usize) & csr::SSTATUS_SPP == 0;

            // A kernel fault always prints; a user task's is rate limited
            // (`user_fault_report`), its kill and exit status are not.
            let show = !from_user || user_fault_report();
            if show {
                azos_drv_sys::kwarn!();
                azos_drv_sys::kwarn!("[EXCEPTION] CPU {} — {}", hart, trap::cause_str(cause));
                azos_drv_sys::kwarn!("  sepc:   {:#x}", frame.sepc);
                azos_drv_sys::kwarn!("  stval:  {:#x}", frame.stval);
                azos_drv_sys::kwarn!("  scause: {:#x}", frame.scause);
                azos_drv_sys::kwarn!("  regs[1] (ra):  {:#x}", frame.regs[1]);
                azos_drv_sys::kwarn!("  regs[2] (sp):  {:#x}", frame.regs[2]);
            }

            if from_user {
                // Ring-3 executed something it had no business executing.
                // Kill just that task, like the page-fault arm does.
                //
                // Deliberately NO `motor_cmd_publish(0, 0)` on this path, and
                // the page-fault arm makes the same choice: the dead task is
                // one of many, the control loop and the reflex daemon are
                // still running, and slamming the motors to zero from a trap
                // handler would inject a stop command that the surviving
                // control stack neither requested nor knows about — worse
                // than useless on a robot mid-motion. Emergency stop belongs
                // to the S-mode branch, where nothing is left to steer.
                if show {
                    azos_drv_sys::kwarn!("[EXCEPTION] Killing user task '{}' (tid {})",
                        azos_sched::current_task_name(),
                        azos_sched::current_task_tid());
                }
                // scause → the status `waitpid` reports (128 + signal), not 0.
                use azos_abi::exit_status as es;
                let code = match cause {
                    0 | 4 | 6 => es::KILLED_BUS,    // misaligned fetch/load/store
                    1 | 5 | 7 => es::KILLED_SEGV,   // access faults (PMP)
                    3 => es::KILLED_TRAP,           // ebreak
                    _ => es::KILLED_ILL,            // 2 = illegal instruction, rest
                };
                azos_sched::scheduler::task_exit_by_signal(code);
                // task_exit() never returns — context_switch abandons this frame.
            } else {
                // S-mode: the kernel itself hit a bad instruction or a
                // misaligned access. Nothing here is recoverable — there is no
                // smaller unit than "the kernel" left to kill — so stop the
                // motors to prevent a runaway and go down.
                #[cfg(feature = "domain-robot")]
                azos_robot::motor_cmd_publish(0, 0);
                crate::panic::halt_begin();
                azos_drv_sys::kerr!("[FATAL] Unhandled exception on CPU {} — shutdown", hart);
                crate::panic::halt_report();
                azos_arch::Boot::shutdown(&azos_arch::ARCH);
            }
        }
    }
}

/// Console reports of user tasks killed by a fault: a burst of 10 per 5 s,
/// then one line counting what was dropped (Linux's `printk_ratelimit`
/// defaults). A program that faults in a loop would otherwise fill the
/// console. Only the report: the kill, the exit status and every record
/// (lease faults, `SAFETY_COW_OOM`) still happen each time.
static USER_FAULT_REPORTS: azos_drv_sys::ratelimit::RateLimit =
    azos_drv_sys::ratelimit::RateLimit::new(10, 5);

/// Whether this user-fault report prints; prints the suppressed count first
/// when reports were dropped since the last one.
#[inline(never)]
fn user_fault_report() -> bool {
    match USER_FAULT_REPORTS.check() {
        Some(0) => true,
        Some(k) => {
            azos_drv_sys::kwarn!("[FAULT] {} user-task fault report(s) suppressed", k);
            true
        }
        None => false,
    }
}

/// Wave 11 (LEASE2): a user fault inside a lease mapping the kernel already
/// revoked — the lessee touched its buffer after return, expiry or the
/// lessor's free. Recorded (`SYS_EXIT_STATS` selector
/// `EXIT_STAT_LEASE_REVOKED_FAULTS`) and named; the task is killed by the
/// caller as for any unresolved fault. aarch64's kill path
/// (`entry::aarch64::handle_page_fault`) makes the same call.
pub(crate) fn page_fault_note_lease(va: usize, show: bool) {
    let tid = azos_sched::current_task_tid();
    if let Some(lease) = azos_ipc::lease::lease_revoked_fault(tid, va).filter(|_| show) {
        azos_drv_sys::kwarn!(
            "[LEASE] task {} touched lease {} mapping at {:#x} after it was revoked: recorded ({} since boot)",
            tid, lease, va, azos_ipc::lease::lease_revoked_faults(),
        );
    }
    // Wave 11 (LEASE3): a lessor writing its own buffer under a seal.
    if let Some(lease) = azos_ipc::lease::lease_sealed_fault(tid, va).filter(|_| show) {
        azos_drv_sys::kwarn!(
            "[LEASE] task {} wrote its buffer at {:#x} while lease {} sealed it: recorded ({} since boot)",
            tid, va, lease, azos_ipc::lease::lease_seal_faults(),
        );
    }
}

/// Wave 13: deliver signals (or apply a `rt_sigreturn`) to the current task
/// at its return to user mode, from a syscall (`from_syscall`) or an
/// interrupt taken from U-mode. Out of line and not `#[cold]`: a cold callee
/// reshapes the hot caller (`seccomp_deny_kill`'s note in `dispatch.rs`).
///
/// Only `x1..x31` and `sepc` are written back: `sstatus` never comes from a
/// user frame, so a sigreturn cannot raise its own privilege.
#[cfg(target_arch = "riscv64")]
#[inline(never)]
pub(crate) fn signal_return(frame: &mut trap::TrapFrame, from_syscall: bool) {
    use azos_linux_abi::signal as sig;
    let mut ctx = sig::Context {
        gpr: core::array::from_fn(|i| frame.regs[i] as u64),
        pc: frame.sepc as u64,
        pstate: 0,
    };
    let changed = azos_syscall::linux::on_return_to_user(
        &mut ctx,
        from_syscall,
        // f0..f31 and fcsr, the save area's own layout (zero when the task
        // has not used the file).
        &mut |w| match azos_sched::fp::frame_save() {
            Some(a) => {
                w[..33].copy_from_slice(&a);
                true
            }
            None => false,
        },
        &mut |w| {
            let mut a = [0u64; 33];
            a.copy_from_slice(&w[..33]);
            a[32] &= 0xffff_ffff;
            azos_sched::fp::frame_load(&a);
        },
    );
    if changed {
        for i in 1..32 {
            frame.regs[i] = ctx.gpr[i] as _;
        }
        frame.sepc = ctx.pc as _;
    }
}
