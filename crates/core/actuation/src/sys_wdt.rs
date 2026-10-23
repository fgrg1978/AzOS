// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The system watchdog task (Phase 16).

use core::sync::atomic::Ordering;
use azos_drv_sys::kprintln;

use crate::watchdog::TICK_COUNT;

azos_common::ro_hook! {
    /// The OTA boot-good mark, with its delay in [`BOOT_GOOD_DELAY_S`].
    ///
    /// `azos_ota` is a scaffolding crate, so this crate cannot name
    /// `OTA_BOOT_GOOD_DELAY_S` or `ota_mark_boot_good`. The kernel links both
    /// sides and installs them here with [`set_boot_good_hook`] before it spawns
    /// `sys-wdt`. Installed, `system_wdt_task` marks the boot good exactly as it
    /// did when it called `azos_ota` directly: once, on the first pass with
    /// `delay_s` seconds of uptime.
    ///
    /// Not installed, the task never marks the boot good; it checks again on every
    /// pass and marks on the first pass after an install. Nothing else in the
    /// watchdog changes. The effect lands in OTA: BOOTMETA's `boot_count` is never
    /// reset, so on the boot after `CFG_OTA_MAX_BOOT_ATTEMPTS` unmarked boots
    /// `ota_boot_validate` rolls the active slot back to `last_good`.
    static BOOT_GOOD_HOOK: fn();
}
/// Seconds after boot the mark waits for ([`set_boot_good_hook`]).
static BOOT_GOOD_DELAY_S: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Install the OTA boot-good mark. Called once by the kernel, before it spawns
/// `system_wdt_task`.
pub fn set_boot_good_hook(delay_s: u32, mark: fn()) {
    BOOT_GOOD_DELAY_S.store(delay_s, core::sync::atomic::Ordering::Relaxed);
    BOOT_GOOD_HOOK.set(mark);
}

/// Phase 16: system watchdog task.
///
/// Each pass starts by blocking on a timer deadline 500 ms ahead
/// (`WaitReason::Timer`, `TIMER_FREQ / 2`), then:
///
/// 0. **Effect deadlines** (Kconfig `EFFECT_WRITE_AHEAD`) — `safe_state::sweep`:
///    a watched effect overdue at this pass has its device driven to the
///    safe state the kernel declares for it, one `Rule::SafeState` record
///    (innovation B2). This pass is the timer of that watch, so a stalled
///    device is safe within its deadline plus one pass.
///
/// 1. **Stack canaries** — `stack_canary_check()`; if any canary was
///    overwritten, latches the e-stop, records it durably, stops both
///    motors and disarms the ESC (U08-1, owner decision 2026-09-26 — before
///    then this stopped the motors without latching, and `rt_motor_task`'s
///    next tick undid it).
///
/// 2. **Timer liveness** — compares `TICK_COUNT` with the previous pass. A pass
///    on which it did not advance is a stall; when the consecutive stall count
///    reaches `WDT_FROZEN_THRESHOLD` — 200 under `feature = "qemu"`, 3
///    otherwise — latches the e-stop, records it durably, stops both motors
///    and disarms the ESC (same U08-1 decision as section 1).
///
/// 3. (The GPIO kill switch was a sample of `estop_gpio_pin` here, once per
///    pass: up to 500 ms to the stop. It is its own task now, woken by the
///    pin's edge interrupt: `kill_switch::kill_switch_task`.)
///
/// 3b. **Flush** — the pending capability-denial summary, then a flush
///    request to the `log-flush` task (this task is RT and never does block
///    I/O itself).
///
/// 4. **Driver health** — `driver_check_health` with the time in ms.
///
/// 5. **OTA boot-good mark** — once, through `BOOT_GOOD_HOOK`, handed to the
///    `log-flush` task (it writes BOOTMETA).
pub fn system_wdt_task(_: usize) {
    kprintln!("[WDT] Phase 16 system watchdog running");
    let mut last_tick    = TICK_COUNT.load(Ordering::Relaxed);
    let mut frozen_count = 0u32;
    let mut boot_good_marked = false;
    // Set once, the first time section 2 finds the tick source unfed — see
    // the `now_tick == 0` arm there.
    let mut tick_source_reported = false;
    // The boot-good delay is measured on the MONOTONIC COUNTER, not on
    // `TICK_COUNT`, and that is a correctness change on both ISAs rather
    // than an aarch64 accommodation:
    //
    //   * `TICK_COUNT` is incremented by EVERY hart's timer ISR into one
    //     global, so `elapsed_ticks / sched_hz` on a 4-hart board reported
    //     four seconds per elapsed second. riscv64 was marking the boot good
    //     after ~7.5 s of a 30 s delay.
    //   * On aarch64 it was not incremented at all until 2026-09-24: that
    //     ISA's timer ISR keeps its own `TICK_COUNT` and did not call
    //     `watchdog::tick()`, so the quotient was a constant 0 and the boot
    //     would never have been marked good however long it ran. That ISR
    //     now calls it; the monotonic-counter delay below is correct on both
    //     ISAs regardless, which is why it stays.
    //
    // `timebase::now()` is `ARCH.now_ticks()` — `mtime` on RISC-V,
    // `CNTVCT_EL0` on aarch64 — and `TIMER_FREQ` is that counter's own
    // per-board rate, so the quotient is seconds on any board either ISA
    // boots on, with no per-hart term to multiply it.
    let boot_start_count = azos_drv_sys::timebase::now();

    // Periodic auto-report of WCET stats so the bench harness
    // can collect per-function samples even when shell-injection of the
    // `wcet` command fails (UART IRQ on a different hart under SMP TCG).
    // Only enabled under `feature = "qemu"` — on real hardware the shell
    // works reliably and the operator can dump on demand.
    //
    // WDT iterates every 500 ms (see WDT_CHECK_INTERVAL_DIV).  Report every
    // 60 iterations ≈ 30 s — long enough not to spam UART, short enough
    // that a 40 s bench scenario sees at least one report.
    // The auto-report originally lived here in `system_wdt_task`, but
    // empirical observation (2026-05-29 bench) showed sys-wdt never reaches its
    // loop body under QEMU TCG — only the early-boot "[WDT] crash counter reset"
    // line emits, then nothing.  Moved the auto-report to `behavior_task` which
    // demonstrably runs (visible via [BRAIN] log entries throughout bench).
    // sys-wdt liveness is a separate preexisting issue, tracked separately.

    loop {
        // Spin-yield until ~500 ms of *real* time has elapsed, measured via the
        // mtime counter (which keeps advancing even if the timer *interrupt* is
        // frozen — exactly the failure this watchdog must still detect, so we
        // must NOT block on a Timer deadline here). The old loop did
        // `for _ in 0..sched_hz/2 { yield }`, but yields are not time delays —
        // they return near-instantly, so the liveness check below ran thousands
        // of times per second and mis-read the tickless timer's sparse
        // TICK_COUNT advances as false "stalls" (flooding the log). Gating on a
        // real mtime interval makes a non-advancing TICK_COUNT mean what it
        // should: the timer ISR genuinely stopped firing.
        const WDT_CHECK_INTERVAL_DIV: u64 = 2; // TIMER_FREQ / 2 = 500 ms
        let check_interval = azos_drv_sys::timebase::TIMER_FREQ / WDT_CHECK_INTERVAL_DIV;
        let check_start = azos_drv_sys::timebase::now();
        azos_sched::task_block(azos_sched::WaitReason::Timer(
            check_start + check_interval));

        // WHAT CHANGED HERE, AND WHAT IT COSTS.
        //
        // This was a spin on `task_yield` until 500 ms of mtime had passed,
        // deliberately: mtime keeps advancing even when the timer INTERRUPT is
        // frozen, which is the failure section 2 below exists to name, so the
        // old code refused to block on a timer deadline.
        //
        // That reasoning was sound and is now paid for elsewhere. This task
        // runs at RT priority (see `WATCHDOG_PRIORITY`), and a 500 ms yield
        // spin at RT priority starves its own hart — the exact defect K-C27
        // closed for the other daemons. Since the task must run at all before
        // any of its checks mean anything, and it cannot both spin and be
        // RT, it blocks.
        //
        // The freeze case is not lost, it moves to where it always belonged:
        // the HARDWARE watchdog is kicked from the timer ISR itself, gated on
        // `CONTROL_HEARTBEAT`. A frozen ISR stops kicking it and the board
        // resets — a backstop that does not depend on the scheduler, unlike
        // this task. What section 2 keeps is the case it can still observe: a
        // timer that STALLS between two wakes rather than stopping outright.
        // Under `feature = "qemu"` it was already thresholded to 200 stalls
        // because TCG false-positives, so nothing measurable is given up here.


        // ── 0. Effect deadlines ────────────────────────────────────────────
        // First, before anything below that could take its time: the sweep
        // is lock-free and bounded by the watch table.
        #[cfg(feature = "effect-gate")]
        crate::safe_state::sweep(azos_drv_sys::timebase::now());

        // ── 1. Stack canary check ─────────────────────────────────────────
        let (ok, total) = azos_sched::stack_canary_check();
        if ok < total {
            // Owner decision, 2026-09-26 (U08-1): LATCH, not just stop. This
            // used to call `motor_stop(0)`/`motor_stop(1)` directly and
            // nothing else — no `estop_activate()`, so the stop lasted
            // exactly until `rt_motor_task`'s next tick (≤1 ms) rewrote both
            // wheels from whatever `MotorCmd` arrived next; `motor_envelope`
            // only refuses a command while `estop_is_active()` holds, and
            // nothing here ever set it. A kernel that just found its OWN
            // stack corrupted is the case where the wheels must not be
            // trusted to any further command until an operator clears the
            // latch — see `actuation::latch_and_stop`'s own doc for why the
            // latch precedes the wheels. No record was written either.
            azos_drv_sys::kerr!("[WDT] STACK OVERFLOW: {}/{} canaries intact — motors stopped, envelope latched",
                ok, total);
            crate::gate::latch_and_stop();
            let _ = crate::logger::log_safety_violation_durable(
                crate::logger::SAFETY_ESTOP,
                crate::estop::ESTOP_ACTION_STACK_OVERFLOW,
                (total - ok) as u32);
        }

        // ── 2. Timer liveness check ───────────────────────────────────────
        // Threshold: 3 stalls on hardware (where 1.5 s of frozen timer is
        // unambiguously catastrophic) but much higher on QEMU TCG — the
        // 4-SMP TCG translator can wall-stall multiple consecutive
        // yields without any real timer fault (the E2E wheeled run was
        // tripping SAFE STOP every other cycle on a healthy kernel).
        // The SAFE STOP itself is also a no-op on QEMU (no real motors)
        // so the only effect of a false positive is log noise + motor
        // calls that go nowhere — but the cascade hides the real boot
        // log, which IS the problem we hit.
        #[cfg(feature = "qemu")]
        const WDT_FROZEN_THRESHOLD: u32 = 200;
        #[cfg(not(feature = "qemu"))]
        const WDT_FROZEN_THRESHOLD: u32 = 3;

        let now_tick = TICK_COUNT.load(Ordering::Relaxed);
        // A counter still at its initial 0 while this task is being SCHEDULED
        // is not a frozen clock — it is an unfed one, and the two must not be
        // answered the same way. This task only runs because a timer
        // interrupt is preempting somebody, so a genuinely frozen timer here
        // leaves `now_tick` at whatever it had already reached, never at 0.
        //
        // Measured, and the reason this arm was written: until 2026-09-24
        // aarch64's timer ISR incremented only its OWN `TICK_COUNT` and never
        // called `watchdog::tick()`, so the counter this section reads was fed
        // by nothing on that ISA. Without this arm, `sys-wdt` on ARM would
        // have counted `WDT_FROZEN_THRESHOLD` stalls of a perfectly healthy
        // timer and called SAFE STOP on the motors — a watchdog inventing the
        // failure it exists to catch.
        //
        // **That ISR now calls all three (`tick`, `halt_if_panicked`,
        // `feed_from_timer_tick`), so this arm should no longer fire on
        // either ISA. It stays as a guard, not as a known state**: it is the
        // difference between an unfed counter and a frozen clock, and a
        // future ISA — or a build that reaches this task before the timer is
        // armed — would hit it again. If the INERT line appears in a boot
        // log, something stopped feeding the counter; that is a finding, not
        // noise.
        //
        // Reported once and skipped, NOT silently skipped: an inert liveness
        // check has to say so, or the next reader takes the absence of stall
        // lines as proof the timer is fine.
        if now_tick == 0 {
            if !tick_source_reported {
                tick_source_reported = true;
                azos_drv_sys::kwarn!("[WDT] timer liveness INERT: watchdog::TICK_COUNT is \
                           not being fed — the stall check is skipped, not passing");
            }
        } else {
            if !tick_source_reported {
                // **The positive half of the pair, and the gate reads THIS
                // one.** Asserting that the INERT line is ABSENT would prove
                // nothing: a kernel that never reached this task, or a marker
                // someone renamed, is also "absent". So the live state gets
                // its own line, carrying the count that makes it live.
                tick_source_reported = true;
                kprintln!("[WDT] timer liveness ACTIVE: watchdog::TICK_COUNT={}",
                          now_tick);
            }
            if now_tick == last_tick {
                frozen_count += 1;
                // Only log the first stall and the SAFE STOP — flooding the
                // UART with one line per polled-but-not-advanced check costs
                // ~milliseconds per line and *worsens* the apparent stall.
                if frozen_count == 1 {
                    azos_drv_sys::kwarn!("[WDT] Timer stall starting (tick_count={})", now_tick);
                }
                if frozen_count == WDT_FROZEN_THRESHOLD {
                    // Owner decision, 2026-09-26 (U08-1): same fix as the
                    // stack-canary branch above — LATCH through the e-stop,
                    // not a bare `motor_stop` the next command undoes within
                    // one control tick. A timer that just resumed stalling
                    // for `WDT_FROZEN_THRESHOLD` consecutive 500 ms passes
                    // is not a state `rt_motor_task` should be trusted to
                    // drive out of on its own next tick.
                    azos_drv_sys::kerr!("[WDT] Timer FROZEN after {} stalls — SAFE STOP, envelope latched",
                              frozen_count);
                    crate::gate::latch_and_stop();
                    let _ = crate::logger::log_safety_violation_durable(
                        crate::logger::SAFETY_ESTOP,
                        crate::estop::ESTOP_ACTION_TIMER_FROZEN,
                        frozen_count);
                }
            } else {
                if frozen_count > 0 {
                    azos_drv_sys::kwarn!("[WDT] Timer resumed after {} stalls", frozen_count);
                    frozen_count = 0;
                }
                last_tick = now_tick;
            }
        }

        // ── 3b. Push the safety record to disk ──────────────────────────
        //
        // Safety events are rare by design, and the ring only flushes itself
        // when it is half full — so without this they would sit in RAM and be
        // lost on the very reset they exist to explain. `logger_flush` is
        // best-effort and returns the count it wrote; a failure here must not
        // stop the watchdog doing its actual job.
        //
        // Here rather than at the call sites: this task wakes every ~500 ms,
        // so the request is the periodic flush. The write itself runs in the
        // `log-flush` task, outside the RT band.
        // A flood that stopped has no further denial to close its window;
        // write its count now, so this pass's flush carries it to disk.
        azos_syscall::handlers::cap_denial_flush_pending();
        // This task is RT (11): it never does block I/O (owner rule, wave
        // 15). The `log-flush` task writes the ring; this only wakes it.
        crate::logger::logger_request_flush();

        // ── 4. Driver health check (AQ2) ────────────────────────────────
        // Detect stalled drivers (no heartbeat) and trigger auto-restart.
        // `driver_check_health` compares against `last_heartbeat` which is
        // stored in *milliseconds* (no ring-3 call sets it any more), so convert
        // the raw mtime counter to ms before passing. Was previously called
        // with raw ticks — latent today (no heartbeating drivers) but would
        // have crash-looped every registered driver the moment one shipped.
        let now_ms = azos_drv_sys::timebase::now()
            / (azos_drv_sys::timebase::TIMER_FREQ / 1000);
        azos_sched::driver_check_health(now_ms);

        // ── 5. OTA boot-good mark ────────────────────────────────────────
        // After OTA_BOOT_GOOD_DELAY_S of successful uptime, mark boot as good.
        if !boot_good_marked {
            // Monotonic counter, not `TICK_COUNT` — see `boot_start_count`'s
            // own comment at the top of this function for the two defects
            // that reading the tick counter here carried.
            let elapsed_s = azos_drv_sys::timebase::now()
                .wrapping_sub(boot_start_count)
                / azos_drv_sys::timebase::TIMER_FREQ;
            if let Some(mark_boot_good) = BOOT_GOOD_HOOK.get() {
                let boot_good_delay_s = BOOT_GOOD_DELAY_S.load(core::sync::atomic::Ordering::Relaxed);
                // The mark writes BOOTMETA: block I/O, which this RT task
                // hands to the `log-flush` task (owner rule, wave 15). A full
                // job table is retried on the next pass.
                if elapsed_s >= boot_good_delay_s as u64
                    && crate::logger::logger_defer_io(mark_boot_good)
                {
                    boot_good_marked = true;
                }
            }
        }

    }
}
