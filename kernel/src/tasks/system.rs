// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Always-on system tasks: the per-hart idle task (one per ISA) and the shell.

use azos_arch::{ArchEntry as _, Cpu as _};
// Only `idle_task`'s `ipc-census` block names a crate-root item (`kprintln!`).
#[cfg(all(target_arch = "riscv64", feature = "ipc-census"))]
use crate::*;

/// One idle wait of the calling hart, through the RFC-0051 `IdleGovernor`
/// seam (stage E0: `WfiOnly`, a `const`, so this folds to the bare `wfi` both
/// idle tasks executed before the seam existed). The next armed timer is
/// asked for lazily: only a governor that needs it will compute it.
#[cfg(not(feature = "energy"))]
#[inline(always)]
fn idle_wait() {
    match azos_energy::seams::IDLE_GOVERNOR
        .select_state(azos_sched::smp::current_cpu_id, azos_sched::nearest_timer_deadline)
    {
        azos_energy::IdleChoice::Wfi | azos_energy::IdleChoice::Deep(_) => azos_arch::ARCH.wfi(),
    }
}

/// With `energy`: the governors the boot selected (`Seams::select`), E3's
/// frequency decision at idle entry and E4's idle-state choice, every state
/// entered as `wfi` (`azos_sched::energy::idle_wait`).
#[cfg(feature = "energy")]
#[inline(always)]
fn idle_wait() {
    azos_sched::energy::idle_wait(azos_sched::smp::current_cpu_id(), || azos_arch::ARCH.wfi());
}

/// Refresh the vDSO timing page as an idle hart wakes (wave 13, owner
/// decision round 50). Every timer interrupt refreshes it, as before; this
/// covers a wake by IPI or device interrupt, which used to rely on hart 0's
/// fixed idle keepalive having refreshed it within 100 ms. Hart 0 now has no
/// keepalive unless a watchdog is armed, so a ring-3 task woken by anything
/// but a timer must not read a page from the last timer interrupt, possibly
/// seconds old. While every hart is idle no ring-3 code runs, so a page
/// refreshed at each wake is never older than the page a running hart's own
/// tick keeps.
#[inline(always)]
fn vdso_refresh_on_wake() {
    // The ISA's clock source (`ArchEntry::vdso_clock`): riscv64 `rdtime` at
    // the fixed `TIMER_FREQ` and the watchdog tick; aarch64 `CNTVCT_EL0` at
    // the live `CNTFRQ_EL0` once known. `None` under `no-mmu` (no vDSO page).
    if let Some((ticks, ms)) = crate::ARCH_ENTRY.vdso_clock() {
        azos_mm::vdso::vdso_update(ticks, ms);
    }
}

/// Idle task, one per CPU, pinned: runs when no other task is ready on this
/// CPU. The same body on every ISA; only the `ipc-census` wake-latency
/// report is riscv64's (CLINT counters with no aarch64 equivalent).
pub(crate) fn idle_task(_arg: usize) {
    loop {
        // QSBR (Kconfig RCU_QSBR, N4): an idle CPU is in an extended
        // quiescent state, so a tickless one never holds a grace period.
        // Gate canary `canary=rcu-idle-qs-skip`: it never says so, and the
        // stall detector must catch it (ktest `rcu_idle_cpu_is_quiescent`).
        if !canary!("rcu-idle-qs-skip") {
            azos_sync::qsbr::idle_enter();
        }
        idle_wait();
        azos_sync::qsbr::idle_exit();
        vdso_refresh_on_wake();
        // **The yield is not optional.** `wfi` returns as soon as any
        // interrupt is pending -- including the software IPI a remote hart
        // rings after enqueueing a task here. Without a reschedule right
        // after, this loop goes straight back to `wfi` and the newly-ready
        // task waits for the next 100 Hz timer tick instead. Measured with
        // the bare loop: an IPC round trip cost 13 ms, ~8000x the syscall
        // floor, with the doorbell firing correctly the whole time -- the
        // wake arrived, and idle slept through it.
        azos_sched::task_yield();

        // A console residual a budget-limited release left with no later
        // writer to drain it: on a quiet system only idle runs, and hart 0's
        // 100 ms keepalive brings it here. One relaxed load when nothing is
        // stranded (`uart::console_idle_drain`).
        azos_drv_sys::uart::console_idle_drain();

        // The K-C25 reaper's safety net (w14): a full walk here, never in the
        // tick, for a stamp whose waker forgot the flag. One load when no
        // stamp was made since the last walk; a wake it delivers is run
        // before `wfi` (`scheduler::reap_idle_sweep`).
        if azos_sched::scheduler::reap_idle_sweep() {
            azos_sched::task_yield();
        }

        // Wake-latency report (vsbench, the 5-15 ms `ipc-rt` max).
        //
        // **Printed from here on purpose.** The census task does not exist
        // in a `bench-minimal` build without `ipc-census`, which is how the
        // gate column of vsbench is built (the product column
        // runs the full daemon set) -- a first attempt to read these counters from the census
        // produced four empty lines and no error. `idle` is the one task that
        // always exists, and it is about to `wfi` anyway, so a UART write costs
        // nothing that was going to be used.
        //
        // Rate-limited to changes: printing on every idle pass would perturb
        // the very latency being measured.
        #[cfg(all(target_arch = "riscv64", feature = "ipc-census"))]
        {
            use core::sync::atomic::{AtomicU32, Ordering};
            static LAST: AtomicU32 = AtomicU32::new(0);
            let (long, long_rang, max_d, measured) = azos_sched::wakelat_read();
            if long != LAST.swap(long, Ordering::Relaxed) {
                // CLINT is 10 MHz on QEMU, so ticks/10 == microseconds.
                let (wtid, wsite, whart, b1, b2, b4, b8) = azos_sched::wakelat_worst();
                kprintln!("[WAKELAT] worst tid={} armed_by={} on_hart={} dispatched_by_hart={} | 1-2ms={} 2-4ms={} 4-8ms={} >8ms={}",
                    wtid, wsite & 0x0F, wsite >> 4, whart, b1, b2, b4, b8);
                let (isent, ierr, irecv) = azos_sched::wakelat_ipi();
                kprintln!("[WAKELAT] ipi sent={} err={} recv={}", isent, ierr, irecv);
                kprintln!("[WAKELAT] canary={:#x} long={} of {} (bell_rung={} not_rung={}) max={} us",
                    azos_sched::wakelat_canary(),
                    long, measured, long_rang, long - long_rang,
                    max_d / 10);
            }
        }
    }
}

/// Shell task: interactive UART shell — since RFC-0055 the recovery console.
/// It runs only once `console_mode` says no user shell has the console, and
/// it owns console input (`uart::CONSOLE_RX`) from then on.
pub(crate) fn shell_task(_arg: usize) {
    crate::console_mode::wait_for_recovery();
    azos_shell::shell_run()
}
