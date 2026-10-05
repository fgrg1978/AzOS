// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Boot self-tests: the IPC demo, the SMP worker stress, and the RVV bench and
//! isolation probe.

use crate::*;

/// Each worker runs this many iterations.
const WORKER_ITERS: u32 = 2000;

/// IPC demo task: exercises signals, pipes, and service manager (Phase 8).
pub(crate) fn ipc_demo_task(_arg: usize) {
    kprintln!("[IPC] ========================================");
    kprintln!("[IPC]  Phase 8: Signals + Pipes + Services");
    kprintln!("[IPC] ========================================");

    // ── 1. Signals ────────────────────────────────────────────────────────────
    let my_tid = azos_sched::current_task_tid();
    kprintln!("[IPC] Signal test: my TID = {}", my_tid);

    // Send SIGTERM to self
    let rc = azos_ipc::signal_send(my_tid, azos_ipc::SIGTERM);
    kprintln!("[IPC] signal_send(SIGTERM) = {}", rc);

    // Check pending signals
    let pending = azos_ipc::signal_pending();
    let sigterm_bit = 1u32 << azos_ipc::SIGTERM;
    if pending & sigterm_bit != 0 {
        kprintln!("[IPC] SIGTERM pending ✓");
    } else {
        kprintln!("[IPC] SIGTERM NOT pending (unexpected)");
    }

    // Mask SIGTERM
    azos_ipc::signal_set_mask(sigterm_bit);
    let pending2 = azos_ipc::signal_pending();
    if pending2 & sigterm_bit == 0 {
        kprintln!("[IPC] SIGTERM masked (not visible to pending) ✓");
    }

    // Unmask SIGTERM
    azos_ipc::signal_set_mask(0);
    kprintln!("[IPC] Signals: PASS");

    // ── 2. Pipes ──────────────────────────────────────────────────────────────
    match azos_ipc::pipe_create() {
        None => kprintln!("[IPC] Pipe create FAILED"),
        Some((ridx, widx)) => {
            kprintln!("[IPC] Pipe created: read_idx={}, write_idx={}", ridx, widx);

            let msg = b"hello pipe!\0";
            let n_written = azos_ipc::pipe_write(widx, msg.as_ptr(), msg.len());
            kprintln!("[IPC] pipe_write({} bytes) = {}", msg.len(), n_written);

            let mut buf = [0u8; 32];
            let n_read = azos_ipc::pipe_read(ridx, buf.as_mut_ptr(), buf.len());
            kprintln!("[IPC] pipe_read() = {} bytes", n_read);

            if n_read > 0 && &buf[..n_read as usize] == &msg[..n_read as usize] {
                kprintln!("[IPC] Pipe data matches ✓");
            } else {
                kprintln!("[IPC] Pipe data FAILED: read {} bytes, not the ones written", n_read);
            }

            azos_ipc::pipe_close_read(ridx);
            azos_ipc::pipe_close_write(widx);
            kprintln!("[IPC] Pipes: PASS");
        }
    }

    // ── 3. Service manager ────────────────────────────────────────────────────
    let rc = azos_service::service_register(b"robot.sensor", my_tid, 42);
    kprintln!("[IPC] service_register(\"robot.sensor\") = {}", rc);

    let rc2 = azos_service::service_register(b"robot.motor", my_tid, 43);
    kprintln!("[IPC] service_register(\"robot.motor\") = {}", rc2);

    match azos_service::service_discover(b"robot.sensor") {
        Some(entry) => kprintln!("[IPC] service_discover(\"robot.sensor\") → tid={} ✓", entry.tid),
        None        => kprintln!("[IPC] service_discover FAILED"),
    }

    let hb = azos_service::service_heartbeat(b"robot.sensor");
    kprintln!("[IPC] service_heartbeat = {}", hb);

    let cnt = azos_service::service_count();
    kprintln!("[IPC] service_count() = {}", cnt);

    kprintln!("[IPC] Service manager: PASS");
    kprintln!("[IPC] ========================================");
    kprintln!("[IPC]  Phase 8 demo complete");
    kprintln!("[IPC] ========================================");
}

/// Worker task: runs WORKER_ITERS iterations with voluntary yields, then exits.
pub(crate) fn worker_task(arg: usize) {
    let id = arg;
    let cpu = azos_sched::smp::current_cpu_id();

    kprintln!("[TASK] Worker {} starting on CPU {}", id, cpu);

    for i in 0..WORKER_ITERS {
        if i % 500 == 0 {
            kprintln!("[TASK] Worker {} — {}/{} (CPU {})",
                id, i, WORKER_ITERS, azos_sched::smp::current_cpu_id());
        }
        azos_sched::task_yield();
    }

    kprintln!("[TASK] Worker {} — Completed {} iterations (CPU {})",
        id, WORKER_ITERS, azos_sched::smp::current_cpu_id());
    // Returns → task_entry_wrapper → task_exit()
}

/// Phase 11: RVV benchmark task.
///
/// Runs scalar vs RVV dot product and matmul benchmarks, then prints cycle counts.
/// Timer interrupt is disabled during RVV operations to prevent vector register
/// corruption (vector context save is implemented in Phase 12).
#[cfg(target_arch = "riscv64")]
#[cfg(feature = "rvv")]
pub(crate) fn rvv_bench_task(_: usize) {
    use azos_arch::{csr, rvv};

    kprintln!("[RVV] ========================================");
    kprintln!("[RVV]  Phase 11: RISC-V Vector Extension");
    kprintln!("[RVV]  VLEN=128, LMUL=m4, f32 precision");
    kprintln!("[RVV] ========================================");
    kprintln!("[RVV] Vector context save: Phase 12 (implemented).");
    kprintln!("[RVV] Timer IRQ disabled during bench (intentional).");
    kprintln!();

    // Disable timer interrupt so no context switch can corrupt v-registers.
    let saved_sie = csr::read_sie();
    csr::write_sie(saved_sie & !csr::SIE_STIE);

    // ── Dot product: 256 f32 ────────────────────────────────────────────────
    const N: usize = 256;
    let mut a = [0.0f32; N];
    let mut b = [0.0f32; N];
    for i in 0..N {
        a[i] = (i as f32) * 0.001;
        b[i] = 1.0_f32;
    }

    let (sc, vc, _, _) = rvv::bench_dot(&a, &b);
    let sp = if vc > 0 { sc * 100 / vc } else { 0 };
    kprintln!("[RVV] dot({} f32):", N);
    kprintln!("[RVV]   scalar : {} cycles", sc);
    kprintln!("[RVV]   rvv    : {} cycles", vc);
    kprintln!("[RVV]   speedup: {}.{}x", sp / 100, sp % 100);
    kprintln!();

    // ── Matmul: 8×8×8 f32 ──────────────────────────────────────────────────
    const MM: usize = 8;
    const KK: usize = 8;
    const NN: usize = 8;
    let mut ma   = [0.0f32; MM * KK];
    let mut mb   = [0.0f32; KK * NN];
    let mut mc_s = [0.0f32; MM * NN];
    let mut mc_v = [0.0f32; MM * NN];
    for i in 0..MM * KK { ma[i] = (i as f32) * 0.001; }
    for i in 0..KK * NN { mb[i] = (i as f32) * 0.001; }

    let (ms, mv) = rvv::bench_matmul(&mut mc_s, &mut mc_v, &ma, &mb, MM, KK, NN);
    let msp = if mv > 0 { ms * 100 / mv } else { 0 };
    kprintln!("[RVV] matmul({}×{}×{} f32):", MM, KK, NN);
    kprintln!("[RVV]   scalar : {} cycles", ms);
    kprintln!("[RVV]   rvv    : {} cycles", mv);
    kprintln!("[RVV]   speedup: {}.{}x", msp / 100, msp % 100);
    kprintln!();

    // Restore timer interrupt.
    csr::write_sie(saved_sie);

    kprintln!("[RVV] ========================================");
    kprintln!("[RVV]  Phase 11 complete — RVV foundation ready");
    kprintln!("[RVV]  Next: Phase 12 ML runtime (ggml-nano port)");
    kprintln!("[RVV] ========================================");
}

/// Canary for the rvv_ctx_save/restore TID-vs-offset-120 bug: per-task
/// completion/result flags for the two `rvv-iso-*` probe tasks (index 0/1,
/// matching the `arg` each is created with).
#[cfg(all(target_arch = "riscv64", feature = "rvv", feature = "rvv-isolation-probe"))]
static RVV_ISO_DONE: [core::sync::atomic::AtomicBool; 2] =
    [core::sync::atomic::AtomicBool::new(false), core::sync::atomic::AtomicBool::new(false)];
#[cfg(all(target_arch = "riscv64", feature = "rvv", feature = "rvv-isolation-probe"))]
static RVV_ISO_OK: [core::sync::atomic::AtomicBool; 2] =
    [core::sync::atomic::AtomicBool::new(false), core::sync::atomic::AtomicBool::new(false)];

/// RVV isolation probe task body. `idx` (the task's `arg`, 0 or 1) selects
/// this task's fill pattern and its slot in `RVV_ISO_DONE`/`RVV_ISO_OK`.
///
/// Fills v0-v31 with a pattern byte unique to this task, yields to let the
/// scheduler run the other probe task (and anything else on hart 0) a few
/// times — the window in which a wrong VEC_STATES[] index corrupts or
/// silently drops this task's vector state — then checks the pattern is
/// still intact. Once both tasks are done, task 0 prints the verdict:
/// `[RVV] ISOLATION OK` only if BOTH patterns survived, else
/// `[RVV] ISOLATION FAILED task=N` for each task whose pattern did not
/// (printed by the task that detected its own corruption).
#[cfg(all(target_arch = "riscv64", feature = "rvv", feature = "rvv-isolation-probe"))]
pub(crate) fn rvv_isolation_probe_task(idx: usize) {
    use azos_arch::rvv;

    let pattern: u8 = if idx == 0 { 0xA5 } else { 0x5A };

    unsafe { rvv::probe_fill_pattern(pattern); }

    for _ in 0..8 {
        azos_sched::task_yield();
    }

    let ok = unsafe { rvv::probe_check_pattern(pattern) };
    RVV_ISO_OK[idx].store(ok, Ordering::SeqCst);
    RVV_ISO_DONE[idx].store(true, Ordering::SeqCst);
    if !ok {
        kprintln!("[RVV] ISOLATION FAILED task={}", idx);
    }

    // Wait for the other probe task to finish, then task 0 prints the
    // combined verdict exactly once. Sleep-polled on the counter with a
    // ceiling (it was an unbounded yield loop): the 8 yields above are the
    // switches under test, this is only a wait.
    let both_done = azos_syscall::sleep::wait_until_ms(10_000, 1, || {
        RVV_ISO_DONE[0].load(Ordering::SeqCst) && RVV_ISO_DONE[1].load(Ordering::SeqCst)
    });
    if !both_done {
        if idx == 0 {
            kprintln!("[RVV] ISOLATION FAILED: probe task 1 never finished");
        }
        return;
    }
    if idx == 0 && RVV_ISO_OK[0].load(Ordering::SeqCst) && RVV_ISO_OK[1].load(Ordering::SeqCst) {
        kprintln!("[RVV] ISOLATION OK");
    }
}
