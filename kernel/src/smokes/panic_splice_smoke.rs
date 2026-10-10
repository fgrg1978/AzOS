// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `panic-splice-smoke` (wave 15, GR5): the panic report reaches the wire
//! whole while another CPU floods the console.
//!
//! Three CPUs (`-smp 3`):
//!
//! * CPU 1 floods the console, alternating the kernel line path
//!   (`kprintln!`) and the ring-3 console path (`uart::console_write_ring3`,
//!   the one a program's `write(1, ..)` takes), interrupts on: the panic's
//!   stop IPI parks it.
//! * CPU 2 joins once [`FLOOD_BEFORE`] lines are out, with kernel lines and
//!   its interrupts masked for good: nothing parks it, so only the console
//!   claim keeps it out of the report (and it shows up as "not parked").
//!   Masked only for the last few milliseconds before the panic, so no
//!   watchdog or grace period notices the CPU.
//! * CPU 0, once [`MASKED_BEFORE`] masked lines are out, takes a `SpinLock` — which
//!   fails the containment predicate under either panic policy, so the reset
//!   path runs every time — and panics.
//!
//! Before Kconfig `PANIC_QUIESCE` the report came out interleaved with the
//! flood (`[AHR!S] Reference!! K pressure` in the gate). The rows
//! (`panic: report not spliced by a console flood`) read the report's lines
//! whole, the parked count, and that the flood was running right up to the
//! banner. Runtime canaries `panic-stop-skip` and `panic-quiesce-skip`
//! (kernel/src/panic.rs `quiesce`).
//!
//! `canary=panic-splice-fatal` (wave 15, GR6) is a mode, not a canary: the
//! culprit reads its own slot's unmapped stack guard page instead, so the
//! kernel page fault's `[FATAL]` halt is judged (rows `fatal: report not
//! spliced by a console flood`). That path takes the same quiesce
//! (`panic::halt_begin`) on every ISA.

use core::fmt::Write as _;
use core::sync::atomic::{AtomicU32, Ordering};

use azos_drv_sys::kprintln;
use azos_drv_sys::timebase::{now, TIMER_FREQ};

/// The culprit's CPU.
const CULPRIT_HART: i8 = 0;
/// The flooder's CPU (interrupts on).
const FLOOD_HART: i8 = 1;
/// The masked flooder's CPU.
const MASKED_HART: i8 = 2;
/// Masked flood lines out before the culprit panics. The masked flooder
/// starts at [`FLOOD_BEFORE`]; this bounds how long CPU 2 stays masked.
const MASKED_BEFORE: u32 = 20;
/// Flood lines out before the culprit panics.
const FLOOD_BEFORE: u32 = 200;
/// Busy gap between two flood lines. Without it the flood outruns the TX
/// ring's drain, the ring is full when the panic starts, and the handler's
/// synchronous flush of it outlasts the flooder's next tick, which parks it
/// before the report: the splice the gate saw needs an empty ring and a
/// writer mid-line. A line every 100 us is still a flood (10 000 lines/s).
const FLOOD_GAP_US: u64 = 100;
/// The culprit's lock: held across the panic, it fails the containment
/// predicate (preemption depth) under either policy, so the reset path runs
/// every time; `lock()`, not `lock_irqsave()`, keeps this CPU's interrupts
/// — and the UART's TX interrupt it serves — on until the handler masks
/// them.
static HELD: azos_sync::SpinLock<u32> = azos_sync::SpinLock::new(0);

/// Flood lines written so far.
static FLOODED: AtomicU32 = AtomicU32::new(0);
/// Masked flood lines written so far.
static MASKED: AtomicU32 = AtomicU32::new(0);

/// Create the flooder and the culprit. Called from `kernel_main` with the
/// other smokes.
pub fn spawn() {
    azos_sched::task_create_affinity("splice-flood", flood_task, 0,
        azos_sched::DEFAULT_PRIORITY, FLOOD_HART);
    azos_sched::task_create_affinity("splice-masked", masked_task, 0,
        azos_sched::DEFAULT_PRIORITY, MASKED_HART);
    azos_sched::task_create_affinity("splice-panic", culprit_task, 0,
        azos_sched::DEFAULT_PRIORITY, CULPRIT_HART);
    kprintln!("[PANIC-SPLICE] flooder on cpu {}, masked flooder on cpu {}, culprit on cpu {}",
        FLOOD_HART, MASKED_HART, CULPRIT_HART);
}

/// One ring-3 style line, formatted on the stack.
struct Line {
    buf: [u8; 96],
    len: usize,
}

impl core::fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let b = s.as_bytes();
        let n = b.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&b[..n]);
        self.len += n;
        Ok(())
    }
}

fn flood_task(_: usize) {
    let mut n = 0u32;
    loop {
        if n % 2 == 0 {
            kprintln!("[FLOOD] {:06} kernel line, the quick brown fox jumps over the lazy dog", n);
        } else {
            let mut line = Line { buf: [0; 96], len: 0 };
            let _ = writeln!(line, "[FLOOD] {:06} ring-3 line, the quick brown fox jumps over the lazy dog", n);
            azos_drv_sys::uart::console_write_ring3(&line.buf[..line.len]);
        }
        n = n.wrapping_add(1);
        FLOODED.store(n, Ordering::Release);
        gap();
    }
}

fn gap() {
    let t0 = now();
    while now().wrapping_sub(t0) < FLOOD_GAP_US * (TIMER_FREQ / 1_000_000) {
        core::hint::spin_loop();
    }
}

fn wait_for_lines(count: &AtomicU32, n: u32) {
    let tick = TIMER_FREQ / 1000;
    while count.load(Ordering::Acquire) < n {
        let deadline = now() + tick;
        while now() < deadline {
            azos_sched::task_block(azos_sched::WaitReason::Timer(deadline));
        }
    }
}

fn masked_task(_: usize) {
    wait_for_lines(&FLOODED, FLOOD_BEFORE);
    let _ = {
        use azos_arch::Interrupts;
        azos_arch::ARCH.disable_all()
    };
    let mut n = 0u32;
    loop {
        kprintln!("[FLOOD] {:06} masked line, the quick brown fox jumps over the lazy dog", n);
        n = n.wrapping_add(1);
        MASKED.store(n, Ordering::Release);
        gap();
    }
}

fn culprit_task(_: usize) {
    wait_for_lines(&FLOODED, FLOOD_BEFORE);
    wait_for_lines(&MASKED, MASKED_BEFORE);
    kprintln!("[PANIC-SPLICE] culprit panicking, {} flood lines out",
        FLOODED.load(Ordering::Acquire));
    let g = HELD.lock();
    if *g == 0 && canary!("panic-splice-fatal") {
        kprintln!("[PANIC-SPLICE] culprit faulting in the kernel");
        // An address no kernel mapping covers on any ISA: a task stack's
        // guard page (ktest `sched_stack_guards_unmapped`).
        let bad = azos_sched::scheduler::stack_guard_addr(0) as *const u64;
        // SAFETY: none; the fault is the point. The read never returns.
        let _ = unsafe { core::ptr::read_volatile(bad) };
    }
    if *g == 0 {
        panic!("panic-splice-smoke: deliberate panic while another CPU floods the console");
    }
}
