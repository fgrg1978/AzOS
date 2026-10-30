// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A timeout written in `TIMER_FREQ` ticks lasts its time by the raw counter and
//! its rate, whatever `CNTFRQ_EL0` is (ktest `clock_timeout_holds_against_counter`;
//! gate rows `aarch64 clock: ...` at 24 MHz under HVF, 19.2 MHz under TCG).

use azos_arch::{Cpu as _, ARCH};
use azos_drv_sys::timebase::{counter_freq, TIMER_FREQ};

const TIMEOUT_MS: u64 = 50;
/// Far above a loaded host's delay, far below the 40-fold of an unscaled clock.
const LATEST_MS: u64 = 1000;

azos_ktest::ktest_late! {
    fn clock_timeout_holds_against_counter() {
        let hz = counter_freq();
        let (c0, t0) = (azos_arch::sysregs::read_cntvct_el0(), ARCH.now_ticks());
        azos_sched::task_block(azos_sched::WaitReason::Timer(t0 + TIMER_FREQ * TIMEOUT_MS / 1000));
        let (c1, t1) = (azos_arch::sysregs::read_cntvct_el0(), ARCH.now_ticks());
        let counter_ms = (c1 - c0) * 1000 / hz;
        let clock_ms = (t1 - t0) * 1000 / TIMER_FREQ;
        azos_drv_sys::kprintln!(
            "# clock: counter {} Hz, clock {} Hz: a {} ms timeout took {} ms by the counter, {} ms by the clock",
            hz, TIMER_FREQ, TIMEOUT_MS, counter_ms, clock_ms
        );
        if counter_ms + 1 < TIMEOUT_MS {
            return Err("the timeout ended early by the counter");
        }
        if counter_ms > LATEST_MS {
            return Err("the timeout ran long by the counter");
        }
        if clock_ms.abs_diff(counter_ms) > 1 + counter_ms / 50 {
            return Err("the clock and the counter disagree about the time");
        }
        Ok(())
    }
}
