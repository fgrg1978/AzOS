// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Panic handler for the kernel.
///
/// SAFETY FIRST: stops all actuators (motors + ESCs) before printing
/// the panic message and halting.  A robot must never continue moving
/// after a kernel panic.
///
/// After stopping motors and printing to UART, stores the crash log entry
/// in reserved RAM that survives a warm reboot (`kernel/src/pstore.rs`,
/// lock-free), then appends it to `/fat/CRASH.LOG` (best-effort, no
/// allocations). When the file write is skipped or fails, the next boot
/// copies the RAM record into the file.
///
/// The panic message itself goes out via `uart::puts`, which is lock-free
/// (see `uart::putc`/`ns16550a::putc_raw` — no software lock, only a
/// hardware busy-wait on the transmitter-ready bit). The actuator-stop
/// calls at the top (`motor_stop_panic`, `esc_disarm_panic`) are also
/// lock-free: they bypass the `MOTORS`/`GPIO`/`PWM` spinlocks and the
/// UART lock respectively, on purpose, so nothing before the first
/// `uart::puts` call below can spin forever on a lock held by another
/// hart. See the doc comments on `motor::motor_stop_panic`,
/// `drivers::gpio::gpio_write_panic`, `drivers::pwm::pwm_set_duty_pct_panic`
/// and `drivers::esc::esc_disarm_panic` for why that trade-off (torn
/// actuator state instead of a hung panic handler) is deliberate.
/// The crash-log write (VFS `FS` lock + FAT32 volume/sector-cache locks)
/// and the trace dump (UART lock, via `kprintln!`) — both further down,
/// after the panic message is already out — are each gated by a
/// non-blocking peek first and skipped with a UART note if the lock isn't
/// free — see `write_crash_log()`.
/// Then optionally reboots after a configurable delay.
///
/// **A panic inside this handler** (owner decision 2026-10-24) prints one
/// line and reboots or halts as the policy says, without the report again
/// ([`nested`]): the handler marks the hart first thing, before any call that
/// could panic.
///
/// **Panic policy (RT7).** Before any of the above, the handler
/// captures the containment predicate's inputs (interrupts still as the
/// panic found them) and asks `azos_common::panic_policy::decide`. Under
/// Kconfig `PANIC_POLICY_CONTAIN` a panic in a non-safety kernel task whose
/// context passes is CONTAINED by [`contain`]: the task is parked through the
/// ordinary exit path and nothing global happens. Every other panic takes
/// the reset path described above, which first prints the verdict and why.
use core::panic::PanicInfo;
use azos_arch::Cpu as _;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use azos_common::panic_policy::{self, Culprit, PanicContext, Policy, Verdict};

/// Maximum crash log entry size (bytes). The path itself now lives in
/// `azos_fs::CRASH_LOG_PATH` — `record_entry` (called below) is the only
/// thing that opens it, so this file no longer needs its own copy.
const CRASH_ENTRY_MAX: usize = 512;
/// Number of most recent trace events to dump on panic (best-effort).
const TRACE_DUMP_EVENTS: usize = 16;

/// The build's policy (Kconfig `PANIC_POLICY`). A constant, so the branch
/// the build did not choose is compiled out of the handler.
const POLICY: Policy = if azos_limits::PANIC_POLICY_CONTAIN {
    Policy::Contain
} else {
    Policy::Reset
};

/// Per-hart "inside the panic handler": the TID being handled plus one,
/// [`ENTERING`] before the handler has read it (and on a `[FATAL]` halt,
/// [`halt_begin`]), 0 = not in the handler. Set first thing on entry
/// ([`enter`]), cleared only by [`contain`] right before it parks the
/// culprit; the reset path never returns, so it never clears it. Holding the
/// TID, not a flag, also catches a contained task that migrated to another
/// hart and panicked again there.
static IN_PANIC: [AtomicU32; azos_sched::MAX_CPUS] =
    [const { AtomicU32::new(0) }; azos_sched::MAX_CPUS];

/// [`IN_PANIC`] of a hart in the handler that has not read the running task.
const ENTERING: u32 = u32::MAX;

/// Per-hart: inside [`nested`]. A panic there parks the hart at once.
static NESTED: [AtomicBool; azos_sched::MAX_CPUS] =
    [const { AtomicBool::new(false) }; azos_sched::MAX_CPUS];

/// Mark the task in pool slot `idx` (as `task_create*` returns it) a safety
/// task: a panic in it is never contained (`panic_policy`, check 6). Says so
/// on the console either way; a refusal leaves that task containable, which
/// the line makes visible.
///
/// The lines must not contain the word "panic" in any case: many gate rows
/// fail a boot whose log matches `panic` case-insensitively, and these print
/// on every robot boot.
#[cfg(feature = "use-robot")]
pub fn register_safety_task(idx: usize, name: &str) {
    use azos_drv_sys::kprintln;
    match azos_sched::tid_for_idx(idx) {
        Some(tid) if panic_policy::register_safety_task(tid) => {
            kprintln!("[SAFETY] {} (tid {}) is a safety task: a fault in it is never contained",
                name, tid);
        }
        _ => azos_drv_sys::kwarn!("[SAFETY] {} NOT registered as a safety task (slot {})", name, idx),
    }
}

/// The handler's first step: mark this hart inside it. True when it already
/// was -- a panic inside this handler, or inside a `[FATAL]` halt's report --
/// or when the hart is past the table and cannot be tracked. One atomic swap:
/// nothing before it can panic again.
#[inline(always)]
fn enter(hart: usize) -> bool {
    IN_PANIC.get(hart).is_none_or(|f| f.swap(ENTERING, Ordering::AcqRel) != 0)
}

/// Put the running task's TID in this hart's mark. True when another hart is
/// handling a panic of the same task: a contained task that migrated in the
/// middle of [`contain`] and panicked again.
fn mark(hart: usize, tid: u32) -> bool {
    let mark = tid.wrapping_add(1);
    if let Some(f) = IN_PANIC.get(hart) {
        f.store(mark, Ordering::Release);
    }
    tid != 0
        && IN_PANIC.iter().enumerate()
            .any(|(h, o)| h != hart && o.load(Ordering::Acquire) == mark)
}

/// Capture what the containment predicate reads, before anything masks
/// interrupts or takes a lock.
fn capture(hart: usize, tid: u32) -> PanicContext {
    let culprit = if tid == 0 {
        Culprit::NoTask
    } else if azos_sched::current_task_name() == "idle" {
        Culprit::Idle
    } else if azos_sched::current_user_pt() != 0 {
        Culprit::User
    } else if panic_policy::is_safety_task(tid) {
        Culprit::Safety
    } else {
        Culprit::Kernel
    };
    PanicContext {
        in_isr: azos_sync::isr_depth::in_isr(hart),
        preempt_depth: azos_sync::preempt::depth(),
        irqs_were_enabled: azos_sync::preempt::irqs_enabled(),
        // Locks nobody else would release: held `Mutex`es, FAT-sector
        // claims (crates/fs/fs/src/fat32.rs, F1: not a mutex, same rule) and
        // the claims held across device waits (F1: the flight recorder's
        // flush claim, the exec bounce buffer, the file descriptor I/O
        // claims; `azos_sync::claim`).
        mutex_held: azos_sync::held::held_by(tid)
            .saturating_add(azos_fs::fat32::fat32_claims_held_by(tid))
            .saturating_add(azos_sync::claim::held_by(tid)),
        already_panicked: azos_common::is_panicked(),
        culprit,
    }
}

/// One piece of the panic report: the UART (lock-free, by the direct path)
/// and, with Kconfig `FB_PANIC_SCREEN`, the framebuffer's panic screen.
#[inline]
fn out(s: &str) {
    azos_drv_sys::uart::puts(s);
    #[cfg(feature = "fb-panic-screen")]
    azos_fb::panic::puts(s);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // ── A panic inside this handler: one line, no second report ─────────
    // Before anything else, the task lookup included: whatever below
    // panicked would panic again on a second pass.
    let hart = azos_arch::ARCH.hart_id();
    if enter(hart) && !canary!("panic-nested-report") {
        nested(info, hart);
    }
    let tid = azos_sched::current_task_tid();
    if mark(hart, tid) && !canary!("panic-nested-report") {
        nested(info, hart);
    }

    // ── Panic policy: decide before masking anything ────────────────────
    let verdict = panic_policy::decide(POLICY, &capture(hart, tid));
    let reason = match verdict {
        Verdict::Contain => contain(info, hart, tid),
        Verdict::Reset(reason) => reason,
    };

    // ── Freeze this hart, flag the panic, stop the actuators ────────────
    freeze();

    // ── Stop the other CPUs and own the console (Kconfig PANIC_QUIESCE) ──
    // Before the first byte of the report: another CPU printing meanwhile
    // spliced it byte by byte (`[AHR!S] Reference!! K pressure: 100586
    // PaERNEL PANIC`, gate row `rt: RT block I/O panics, canary (arm)`).
    let stop = quiesce(hart);

    // ── Print panic info (no locks — we're crashing) ────────────────────
    // Kernel output stops deferring to a ring-3 console owner from here on
    // (one atomic store, lock-free): the trace dump's `kprintln!` below must
    // reach the wire even if the owner never runs again. It also puts the
    // TX ring on the wire first (older output, a parked CPU's partial line
    // included); the leading `\n` below ends that line.
    azos_drv_sys::uart::console_enter_bypass();
    out("\n!!! KERNEL PANIC !!!\n");
    out(match POLICY {
        Policy::Contain => "[PANIC] policy=contain verdict=reset reason=",
        Policy::Reset => "[PANIC] policy=reset verdict=reset reason=",
    });
    out(reason.as_str());
    out("\n");

    if let Some(location) = info.location() {
        out("  at ");
        out(location.file());
        out(":");
        let mut buf = [0u8; 10];
        out(fmt_u32(location.line(), &mut buf));
        out("\n");
    }

    if let Some(msg) = info.message().as_str() {
        out("  ");
        out(msg);
        out("\n");
    }

    // A panic inside a `ktest!` test is that test's `not ok`; the run ends
    // here, the kernel does not unwind (kernel/src/ktest.rs).
    #[cfg(feature = "ktest")]
    crate::ktest::on_panic(info);

    // ── Print CPU and task context ──────────────────────────────────────
    let task_name = azos_sched::current_task_name();
    out("  hart=");
    let mut buf = [0u8; 20];
    out(fmt_usize(hart, &mut buf));
    out(" task=");
    out(task_name);
    out("\n");
    // After the hart/task line: rows read a fixed window below the banner.
    if let Some(stop) = stop {
        stop.report();
    }
    // `canary=panic-nested`: a panic here, inside the report.
    #[cfg(feature = "panic-splice-smoke")]
    crate::smokes::panic_splice_smoke::panic_in_report();

    // ── RAM record first (pstore): lock-free, survives a warm reboot ─────
    // Written before anything below that takes a lock, so a panic inside
    // the filesystem (whose locks make `write_crash_log` skip) still reaches
    // the next boot. `kernel/src/pstore.rs` copies it into /fat/CRASH.LOG.
    {
        let buf = unsafe { &mut *(&raw mut CRASH_BUF) };
        let n = build_entry(buf, info, hart, task_name, false);
        ENTRY_LEN.store(n, Ordering::Relaxed);
    }
    let in_pstore = crate::pstore::panic_record(entry());

    // ── F11.3: Increment crash counter (boot-loop detection) ────────────
    let crashes = azos_drv_sys::wdt::crash_counter_increment();
    azos_drv_sys::uart::puts("[PANIC] Crash counter = ");
    let mut cbuf = [0u8; 10];
    azos_drv_sys::uart::puts(fmt_u32(crashes, &mut cbuf));
    if azos_drv_sys::wdt::crash_counter_is_boot_loop() {
        azos_drv_sys::uart::puts(" [BOOT LOOP DETECTED — safe mode on next boot]\n");
    } else {
        azos_drv_sys::uart::puts("\n");
    }

    // The call chain (Kconfig `PROFILER`; nothing otherwise), by the raw
    // console like the lines above.
    crate::prof::backtrace();

    // The report's core is out. Release the console before the crash-log
    // write: it takes FAT32/VFS locks blocking, and a CPU that did not park
    // may hold one while it waits for the console (see
    // `uart::console_release_panic_owner`). What follows is best-effort.
    azos_drv_sys::uart::console_release_panic_owner();

    // ── Persist crash log to FAT32 (best-effort) ────────────────────────
    write_crash_log(in_pstore);

    // ── Dump last trace events (best-effort — never block on UART) ──────
    // `trace_dump` prints via `kprintln!`, which takes the UART spinlock
    // (`uart::acquire()`). Peek with `try_acquire()` first so a hart
    // holding that lock can never wedge the panic handler.
    // The same peek also puts any kernel output that was deferred behind a
    // ring-3 console owner on the wire, under the lock it just took.
    let uart_free_for_trace = azos_drv_sys::uart::flush_deferred_if_free();
    if uart_free_for_trace {
        azos_ipc::trace::trace_dump(TRACE_DUMP_EVENTS);
    } else {
        azos_drv_sys::uart::puts("[PANIC] UART lock busy — skipping trace dump\n");
    }

    // ── Auto-reboot or halt ─────────────────────────────────────────────
    let delay_ms = azos_config::CFG_PANIC_REBOOT_DELAY_MS.load(Ordering::Relaxed);
    if delay_ms > 0 {
        azos_drv_sys::uart::puts("[PANIC] Rebooting in ");
        let mut dbuf = [0u8; 10];
        azos_drv_sys::uart::puts(fmt_u32(delay_ms, &mut dbuf));
        azos_drv_sys::uart::puts(" ms...\n");
    }
    finish(delay_ms)
}

/// The panic's last step: reboot after `delay_ms` (`CFG_PANIC_REBOOT_DELAY_MS`,
/// runtime config `panic_reboot_ms`), or halt this hart when it is 0.
fn finish(delay_ms: u32) -> ! {
    if delay_ms > 0 {
        // Busy-wait delay (no scheduler available during panic)
        let start = azos_drv_sys::timebase::now();
        let ticks_per_ms = azos_drv_sys::timebase::freq() / 1000;
        let wait_ticks = delay_ms as u64 * ticks_per_ms;
        while azos_drv_sys::timebase::now().wrapping_sub(start) < wait_ticks {
            core::hint::spin_loop();
        }

        // `azos_arch::firmware::reboot()` is the raw riscv64 SBI call and
        // does not exist on other ISAs; `ARCH.reboot()` is the same 1:1
        // wrapper `crates/core/shell`'s `cmd_reboot` and `crates/core/syscall`'s
        // `sys_shutdown` already route through — same call on riscv64,
        // and the only one that exists at all on aarch64 (arch-aarch64's
        // `Boot::reboot` impl, PSCI `SYSTEM_RESET`). Found the hard way:
        // this was the one call in kernel/** that didn't compile on
        // aarch64 once every dependency crate did (Item 2 Stage 5).
        use azos_arch::Boot;
        azos_arch::ARCH.reboot();
    }

    loop {
        azos_arch::ARCH.wfi();
    }
}

/// The reset path's first step, and every halt's: mask interrupts so a tick
/// cannot re-enter the scheduler and resume normal execution on this hart;
/// publish the panic flag so the other harts halt on their next tick (see
/// the timer ISR) and no control path re-commands the actuators; then stop
/// them. The interrupt token is dropped: nothing here returns to restore it.
///
/// The actuators stop through the lock-free hooks their domain registered at
/// boot (robot: motors 0 and 1, then the ESC; `azos_actuation::gate`, wave
/// 11), not `motor_stop`/`esc_disarm`: those take the `MOTORS`/`GPIO`/`PWM`
/// and UART spinlocks, so a hart holding any of them at panic time would
/// wedge this call before any UART output ever went out — see the module
/// doc comment above and the doc comments on `motor_stop_panic`/
/// `esc_disarm_panic`.
fn freeze() {
    let _ = {
        use azos_arch::Interrupts;
        azos_arch::ARCH.disable_all()
    };
    azos_common::set_panicked();
    azos_actuation::gate::run_panic_stop_hooks();
}

/// A panic inside this handler, or inside a `[FATAL]` halt's report: the
/// report is what panicked, and running it again ran into the same fault
/// with a whole handler stacked on the last each time, with nothing to stop
/// it short of the stack's end. So: [`freeze`] (again, if the first pass got
/// that far: it is idempotent), one line by the lock-free direct path — no
/// allocation, no lock, no formatting — and the policy's last step
/// ([`finish`]). No quiesce, crash record, crash counter, crash log or trace
/// dump. A panic in here parks the hart at once, so a panic costs at most
/// two handler entries past the first (what `tools/stack_chain.py` charges).
#[cold]
#[inline(never)]
fn nested(info: &PanicInfo, hart: usize) -> ! {
    // A hart past the table shares the last slot: the slot only parks a
    // third panic, on whichever hart.
    if NESTED[hart.min(NESTED.len() - 1)].swap(true, Ordering::AcqRel) {
        let _ = {
            use azos_arch::Interrupts;
            azos_arch::ARCH.disable_all()
        };
        loop {
            azos_arch::ARCH.wfi();
        }
    }
    freeze();
    let delay_ms = azos_config::CFG_PANIC_REBOOT_DELAY_MS.load(Ordering::Relaxed);
    let mut buf = [0u8; 10];
    azos_drv_sys::uart::puts("\n[PANIC] panic inside the panic handler");
    if let Some(loc) = info.location() {
        azos_drv_sys::uart::puts(" at ");
        azos_drv_sys::uart::puts(loc.file());
        azos_drv_sys::uart::puts(":");
        azos_drv_sys::uart::puts(fmt_u32(loc.line(), &mut buf));
    }
    if delay_ms > 0 {
        azos_drv_sys::uart::puts(": no second report; rebooting in ");
        azos_drv_sys::uart::puts(fmt_u32(delay_ms, &mut buf));
        azos_drv_sys::uart::puts(" ms\n");
    } else {
        azos_drv_sys::uart::puts(": no second report; halted\n");
    }
    finish(delay_ms)
}

/// The first call of every `[FATAL]` and unhandled-trap halt, on every ISA
/// (riscv64 `entry/riscv64/trap.rs` and `entry/riscv64/irq.rs`, aarch64 and x86_64
/// `entry/*.rs`): the reset path's steps before it prints, in its order.
/// Interrupts masked; the panic flag up, which is what parks a CPU that takes
/// the stop IPI or its next tick (`watchdog::halt_if_panicked`); the
/// actuators stopped; the other CPUs stopped and the console claimed
/// ([`quiesce`], Kconfig `PANIC_QUIESCE`); kernel output bypassing a ring-3
/// owner. Before wave 15 GR6 these paths only took the bypass, so another
/// CPU's lines spliced their report. The caller prints its report, then
/// [`halt_report`], then halts.
///
/// Out of line and not `#[cold]`, with no return value: some callers are
/// inlined into a trap entry every syscall takes (a cold callee reshapes
/// the hot caller). What it stopped waits in [`HALT_STOP`].
///
/// It marks the hart inside the panic handler ([`IN_PANIC`]): a panic in the
/// halt's report is a second fault, and takes [`nested`]'s one line.
#[inline(never)]
pub(crate) fn halt_begin() {
    let hart = azos_arch::ARCH.hart_id();
    if let Some(f) = IN_PANIC.get(hart) {
        f.store(ENTERING, Ordering::Release);
    }
    freeze();
    if let Some(stop) = quiesce(hart) {
        HALT_STOP[0].store(stop.want, Ordering::Relaxed);
        HALT_STOP[1].store(stop.parked, Ordering::Relaxed);
        HALT_STOP[2].store(1, Ordering::Release);
    }
    azos_drv_sys::uart::console_bypass_for_halt();
    // A fresh line: a parked CPU may have left a partial one on the wire.
    azos_drv_sys::uart::puts("\n");
}

/// [`halt_begin`]'s [`Stopped`]: `want`, `parked`, and 1 once set. Only the
/// CPU that owns the console writes it; every other halting CPU parks.
static HALT_STOP: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

/// `[PANIC] other CPUs parked: <n>/<m>` after a halt's report (the panic
/// report's line, so one reader serves both); nothing when the quiesce was
/// off.
#[inline(never)]
pub(crate) fn halt_report() {
    // The call chain of the fatal trap (Kconfig `PROFILER`; nothing otherwise).
    crate::prof::backtrace();
    if HALT_STOP[2].load(Ordering::Acquire) == 1 {
        Stopped {
            want: HALT_STOP[0].load(Ordering::Relaxed),
            parked: HALT_STOP[1].load(Ordering::Relaxed),
        }
        .report();
    }
}

/// What [`quiesce`] did: the other online CPUs it asked to stop, and which
/// of them parked within `PANIC_STOP_WAIT_US` (bit = CPU id).
struct Stopped {
    want: u64,
    parked: u64,
}

impl Stopped {
    /// `[PANIC] other CPUs parked: <n>/<m>`, plus the ids that did not park.
    fn report(&self) {
        let mut nbuf = [0u8; 10];
        let mut buf = [0u8; 20];
        azos_drv_sys::uart::puts("[PANIC] other CPUs parked: ");
        azos_drv_sys::uart::puts(fmt_u32((self.parked & self.want).count_ones(), &mut nbuf));
        azos_drv_sys::uart::puts("/");
        azos_drv_sys::uart::puts(fmt_u32(self.want.count_ones(), &mut nbuf));
        let late = self.want & !self.parked;
        if late != 0 {
            azos_drv_sys::uart::puts(" (not parked: cpu");
            for cpu in 0..64 {
                if late & (1 << cpu) != 0 {
                    azos_drv_sys::uart::puts(" ");
                    azos_drv_sys::uart::puts(fmt_usize(cpu, &mut buf));
                }
            }
            azos_drv_sys::uart::puts("; their console writes wait for this report)");
        }
        azos_drv_sys::uart::puts("\n");
    }
}

/// Kconfig `PANIC_QUIESCE`, the reset path's step before it prints:
///
/// 1. Claim the console (`uart::console_claim_for_panic`): from now on any
///    other CPU's write to the UART waits until the report is out. A CPU
///    that finds the console claimed is a second panic racing the first:
///    it parks like any other CPU (Linux's `panic_smp_self_stop`), so the
///    two reports never interleave and the two handlers never wait for each
///    other.
/// 2. Ring every other online CPU (the scheduler's doorbell IPI on every
///    ISA); its handler parks the CPU once the panic flag is set
///    (`watchdog::halt_if_panicked`), as its next tick would have — only up
///    to a tick (or a tickless sleep) later, still printing meanwhile.
/// 3. Wait at most `PANIC_STOP_WAIT_US` for them to park. A CPU with
///    interrupts masked through the whole wait is reported by id; its
///    writes still wait behind step 1.
///
/// Returns `None` when the build or a canary turned it off. Prints nothing:
/// the report comes after the banner ([`Stopped::report`]).
fn quiesce(hart: usize) -> Option<Stopped> {
    if !azos_limits::PANIC_QUIESCE || canary!("panic-quiesce-skip") {
        return None;
    }
    if !azos_drv_sys::uart::console_claim_for_panic() {
        azos_actuation::watchdog::halt_if_panicked();
    }
    let online = azos_sched::smp::NUM_ONLINE_CPUS.load(Ordering::Acquire)
        .clamp(1, azos_sched::MAX_CPUS).min(64);
    let mut want = 0u64;
    for cpu in 0..online {
        if cpu != hart {
            want |= 1 << cpu;
        }
    }
    if canary!("panic-stop-skip") {
        return Some(Stopped { want, parked: azos_common::parked_mask() });
    }
    for cpu in 0..online {
        if want & (1 << cpu) != 0 {
            use azos_arch::Interrupts;
            azos_arch::ARCH.send_ipi(cpu);
        }
    }
    let per_us = (azos_drv_sys::timebase::freq() / 1_000_000).max(1);
    let budget = azos_limits::PANIC_STOP_WAIT_US as u64 * per_us;
    let t0 = azos_drv_sys::timebase::now();
    loop {
        let parked = azos_common::parked_mask();
        if parked & want == want || azos_drv_sys::timebase::now().wrapping_sub(t0) >= budget {
            return Some(Stopped { want, parked });
        }
        core::hint::spin_loop();
    }
}

/// The contained-panic path (`Verdict::Contain`): park the culprit, keep the
/// machine running. Runs in the culprit's own task context, which the
/// predicate proved holds no `SpinLock` or `Mutex`, with interrupts on and
/// outside any interrupt handler — so, unlike the reset path, it may print
/// through the ordinary console and block on the filesystem.
///
/// Not done here, on purpose: the global panic flag, the actuator stop,
/// `console_enter_bypass` (global and permanent), the crash counter (boot-loop
/// detection counts resets only) and the trace dump.
fn contain(info: &PanicInfo, hart: usize, tid: u32) -> ! {
    let task_name = azos_sched::current_task_name();
    azos_drv_sys::kconsoleln!("[PANIC] policy=contain verdict=contain task={} tid={} hart={}",
        task_name, tid, hart);
    if let Some(loc) = info.location() {
        azos_drv_sys::kconsoleln!("[PANIC]   at {}:{}", loc.file(), loc.line());
    }
    if let Some(msg) = info.message().as_str() {
        azos_drv_sys::kconsoleln!("[PANIC]   {}", msg);
    }

    // The record: built on this task's own stack (the reset path's static
    // buffer belongs to it), RAM first, then the file.
    let mut buf = [0u8; CRASH_ENTRY_MAX];
    let n = build_entry(&mut buf, info, hart, task_name, true);
    let in_pstore = crate::pstore::contained_record(&buf[..n]);

    // Published before the culprit is parked: the flight controller starts
    // its Land on the next tick.
    let isolations = panic_policy::note_contained(tid);

    let mut fds = azos_fs::ScratchFds::new();
    let outcome = azos_fs::record_entry(&mut fds, &buf[..n]);
    if outcome.write == azos_fs::WriteResult::Written {
        azos_drv_sys::kconsoleln!("[PANIC] contained: crash log written to /fat/CRASH.LOG");
        if in_pstore {
            crate::pstore::contained_record_persisted();
        }
    } else {
        azos_drv_sys::kconsoleln!("[PANIC] contained: /fat/CRASH.LOG not written ({:?}){}",
            outcome.write,
            if in_pstore { "; the RAM record stays for the next boot" } else { "" });
    }

    azos_drv_sys::kconsoleln!("[PANIC] contained: task {} (tid {}) parked, exit status {}; isolation #{}; \
               control loop untouched", task_name, tid,
        panic_policy::CONTAINED_EXIT_STATUS, isolations);

    // Leaving the handler: a later panic on this hart is a first panic again.
    // Cleared last, so a panic anywhere above is still a second one.
    if let Some(f) = IN_PANIC.get(hart) {
        f.store(0, Ordering::Release);
    }
    azos_sched::task_exit_with_code(panic_policy::CONTAINED_EXIT_STATUS)
}

/// Write the entry `build_entry` formatted to `/fat/CRASH.LOG` (append).
/// `in_pstore`: this panic's RAM record was written by this hart, and is
/// cleared once the file write is confirmed.
///
/// Uses a static buffer — no heap allocations. Best-effort: if FAT32 is
/// unavailable or corrupt, this silently fails (UART output is the
/// fallback). The panic handler must never block, so before touching the
/// VFS this checks — without spinning — whether the locks the write path
/// needs are currently free: the VFS-level `FS` lock
/// (`vfs_fs_lock_available()`) and, since `/fat/CRASH.LOG` is always
/// FAT32-backed, the FAT32 volume/sector-cache locks
/// (`fat32_locks_available()`) that `vfs_open`/`vfs_close` reach into for
/// FAT32 paths. If any of them is held (e.g. some hart panicked while
/// holding it, or is otherwise stuck with it held), the on-disk dump is
/// skipped entirely and that is reported over UART.
///
/// Note these checks are a best-effort guard, not a hard guarantee:
/// another hart can still grab one of these locks in the narrow window
/// between the check and the `vfs_open`/`vfs_write`/`vfs_close` calls
/// below, since those functions acquire and release each lock several
/// times internally rather than holding it for the whole operation.
/// Closing that residual race fully would require converting the VFS's
/// and FAT32 driver's internal locking to non-blocking acquisition
/// throughout, which is out of scope here.
fn write_crash_log(in_pstore: bool) {
    if !azos_fs::vfs_fs_lock_available() {
        azos_drv_sys::uart::puts(
            "[PANIC] FS lock busy — skipping crash log dump to /fat/CRASH.LOG\n");
        return;
    }
    if !azos_fs::fat32_locks_available() {
        azos_drv_sys::uart::puts(
            "[PANIC] FAT32 lock busy — skipping crash log dump to /fat/CRASH.LOG\n");
        return;
    }

    let buf = entry();
    let pos = buf.len();
    if pos == 0 {
        return;
    }

    // Write to FAT32 (best-effort), rotating to /fat/CRASH.OLD first if this
    // entry would push /fat/CRASH.LOG past `azos_fs::CRASH_LOG_CAP` (64
    // KiB / 128 entries). The decision and the open/write/close sequence both
    // live in `crates/fs/fs/src/crash_log.rs`, which `tests/host/fs-tests` exercises
    // on the host — see that module's doc.
    //
    // Rotation is what removed the `MAX_FAT32_PROXY_BYTES` (8 MiB) failure
    // mode this comment used to describe: every `O_APPEND`/`O_RDONLY` open
    // this path performs is now of a file capped at 64 KiB, always far under
    // that 8 MiB proxy ceiling, so the open no longer fails for a huge log —
    // there no longer is one.
    let mut fd_table = azos_fs::ScratchFds::new();
    let outcome = azos_fs::record_entry(&mut fd_table, &buf[..pos]);
    // **Every outcome says which one it was.** This used to print the success
    // line unconditionally whenever the open succeeded — so a crash log that
    // was never flushed, and one that was, looked identical in the last words
    // the board ever prints. On a machine whose black box is the only account
    // of why it stopped, that is the worst place to be optimistic. Extended
    // here to name rotation too: a robot whose crash log was just truncated
    // to make room, or whose `/fat/CRASH.OLD` copy failed, deserves to say so
    // in the same breath as "written" — not print the same line rotation and
    // plain appends both take.
    use azos_fs::WriteResult;
    // The RAM record (pstore) holds the same entry; once the file has it,
    // drop the RAM copy so the next boot does not append it twice.
    if in_pstore && outcome.write == WriteResult::Written {
        crate::pstore::panic_record_persisted();
    }
    match (outcome.write, outcome.rotated, outcome.old_copy_ok) {
        (WriteResult::Written, false, _) => {
            azos_drv_sys::uart::puts("[PANIC] Crash log written to /fat/CRASH.LOG\n");
        }
        (WriteResult::Written, true, true) => {
            azos_drv_sys::uart::puts(
                "[PANIC] Crash log ROTATED: /fat/CRASH.OLD holds the previous \
                 entries, new entry written to /fat/CRASH.LOG\n");
        }
        (WriteResult::Written, true, false) => {
            azos_drv_sys::uart::puts(
                "[PANIC] Crash log ROTATED but /fat/CRASH.OLD copy FAILED — \
                 new entry still written to /fat/CRASH.LOG\n");
        }
        (WriteResult::FlushFailed, _, _) => {
            azos_drv_sys::uart::puts(
                "[PANIC] Crash log FLUSH FAILED: /fat/CRASH.LOG not updated\n");
        }
        (WriteResult::NotWritten, _, _) => {
            azos_drv_sys::uart::puts(
                "[PANIC] Crash log NOT written: /fat/CRASH.LOG could not be opened\n");
        }
    }
}

/// The panic's crash-log entry, built once by [`build_entry`] and used by
/// both the RAM record and `/fat/CRASH.LOG`.
static mut CRASH_BUF: [u8; CRASH_ENTRY_MAX] = [0u8; CRASH_ENTRY_MAX];
static ENTRY_LEN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn entry() -> &'static [u8] {
    let n = ENTRY_LEN.load(Ordering::Relaxed).min(CRASH_ENTRY_MAX);
    unsafe { &(&*(&raw const CRASH_BUF))[..n] }
}

/// Format `[t=..] hart=.. task=.. [CONTAINED ]at file:line message\n` into
/// `buf`; returns its length. No lock, no allocation.
fn build_entry(buf: &mut [u8; CRASH_ENTRY_MAX], info: &PanicInfo, hart: usize,
               task_name: &str, contained: bool) -> usize {
    let mut pos = 0usize;

    // Timestamp (CLINT ticks)
    let ts = azos_drv_sys::timebase::now();
    pos += copy_str(buf, pos, b"[t=");
    pos += copy_u64(buf, pos, ts);
    pos += copy_str(buf, pos, b"] hart=");
    pos += copy_usize(buf, pos, hart);
    pos += copy_str(buf, pos, b" task=");
    pos += copy_str(buf, pos, task_name.as_bytes());
    if contained {
        pos += copy_str(buf, pos, b" CONTAINED");
    }

    if let Some(loc) = info.location() {
        pos += copy_str(buf, pos, b" at ");
        pos += copy_str(buf, pos, loc.file().as_bytes());
        pos += copy_str(buf, pos, b":");
        pos += copy_u32(buf, pos, loc.line());
    }

    if let Some(msg) = info.message().as_str() {
        pos += copy_str(buf, pos, b" ");
        let max = (CRASH_ENTRY_MAX - pos).saturating_sub(2); // room for \n
        let mlen = msg.len().min(max);
        pos += copy_str(buf, pos, &msg.as_bytes()[..mlen]);
    }

    if pos < CRASH_ENTRY_MAX {
        buf[pos] = b'\n';
        pos += 1;
    }
    pos
}

fn copy_str(buf: &mut [u8], pos: usize, s: &[u8]) -> usize {
    let n = s.len().min(buf.len().saturating_sub(pos));
    buf[pos..pos + n].copy_from_slice(&s[..n]);
    n
}

fn copy_u32(buf: &mut [u8], pos: usize, val: u32) -> usize {
    let mut tmp = [0u8; 10];
    let s = fmt_u32(val, &mut tmp);
    copy_str(buf, pos, s.as_bytes())
}

fn copy_u64(buf: &mut [u8], pos: usize, mut val: u64) -> usize {
    let mut tmp = [0u8; 20];
    if val == 0 {
        return copy_str(buf, pos, b"0");
    }
    let mut i = 20;
    while val > 0 {
        i -= 1;
        tmp[i] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    copy_str(buf, pos, &tmp[i..])
}

fn copy_usize(buf: &mut [u8], pos: usize, mut val: usize) -> usize {
    let mut tmp = [0u8; 20];
    if val == 0 {
        return copy_str(buf, pos, b"0");
    }
    let mut i = 20;
    while val > 0 {
        i -= 1;
        tmp[i] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    copy_str(buf, pos, &tmp[i..])
}

/// Format a u32 into a decimal string. Returns the written slice of `buf`.
fn fmt_u32(mut val: u32, buf: &mut [u8; 10]) -> &str {
    if val == 0 {
        buf[0] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&buf[..1]) };
    }
    let mut i = 10;
    while val > 0 {
        i -= 1;
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    unsafe { core::str::from_utf8_unchecked(&buf[i..]) }
}

/// Format a usize into a decimal string. Returns the written slice of `buf`.
fn fmt_usize(mut val: usize, buf: &mut [u8; 20]) -> &str {
    if val == 0 {
        buf[0] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&buf[..1]) };
    }
    let mut i = 20;
    while val > 0 {
        i -= 1;
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    unsafe { core::str::from_utf8_unchecked(&buf[i..]) }
}
