// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 boot self-tests: the FP/SIMD check the banner prints, and the
//! checks `boot::early_main` runs once interrupts are live (the
//! `boot_selftests` hook): `svc` returns, ticks arrive at the expected rate,
//! FP/SIMD survives an interrupt, hart 0 takes interrupts on its own stack,
//! the kernel runs in the TTBR1 half, the granule and TCR are as built.

use core::sync::atomic::Ordering as AOrdering;
use azos_drv_sys::kprintln;
use azos_arch::{timer as arch_timer, Cpu, ARCH};
use crate::boot_hooks::AARCH64_SCHED_HZ;

/// The self-tests that need interrupts live.
#[inline(always)]
pub(crate) fn boot_selftests() {
    let live_hz = arch_timer::freq_hz();
    // ── (a) `svc #0` self-test — must RETURN, not park ──────────────
    let selftest_x0: u64;
    unsafe {
        core::arch::asm!(
            "mov x0, #0",
            "svc #0",
            "mov {0}, x0",
            out(reg) selftest_x0,
            out("x0") _,
            options(nostack),
        );
    }
    if selftest_x0 == crate::entry::aarch64::SELFTEST_SVC_REPLY {
        kprintln!("[TRAP] svc #0 self-test: PASS (returned, x0={:#x})", selftest_x0);
    } else {
        azos_drv_sys::kerr!("[TRAP] FAILED: svc #0 self-test — expected x0={:#x}, got {:#x}",
            crate::entry::aarch64::SELFTEST_SVC_REPLY, selftest_x0);
    }

    // ── (b) N ticks in bounded time ──────────────────────────────────
    //
    // The pass/fail bound below is deliberately NOT derived from
    // `period_ticks` — a bound built from the very period this loop
    // exists to verify cannot catch that period being systematically
    // wrong (the 1 GHz-vs-62.5 MHz QEMU `-cpu` disagreement
    // `arch_timer::freq_hz`'s own call site above warns about, or a
    // bad `AARCH64_SCHED_HZ`): the timeout would simply stretch or
    // shrink to match the same error, and the loop would "pass" no
    // matter what the period actually was. `EXPECTED_MS` is instead
    // computed ONCE from `TICK_TARGET`/`AARCH64_SCHED_HZ` alone — the
    // wall-clock time this test is actually supposed to take — and
    // checked against `elapsed_ms`, which comes from the LIVE
    // `CNTVCT_EL0` delta converted through the LIVE `live_hz`, not
    // from anything this test derived. The loop's own timeout is a
    // generous, unrelated 2-real-second safety cap for a timer that
    // ticks but too slowly or too rarely — it is not what decides
    // pass/fail. It does NOT bound a timer whose line never fires
    // (PPI 27 never enabled): `wfi` runs before the deadline compare, so
    // with no interrupt at all the PE parks here for good — which is
    // what the `a64clk-ppi-canary` gate row relies on.
    const TICK_TARGET: u64 = 5;
    const EXPECTED_MS: u64 = 1000 * TICK_TARGET / AARCH64_SCHED_HZ; // 50 ms
    let ticks_before = crate::entry::aarch64::TICK_COUNT.load(AOrdering::Acquire);
    let target = ticks_before + TICK_TARGET;
    let start_cntvct = ARCH.now_ticks();
    let hard_timeout_ticks = live_hz.saturating_mul(2); // 2 s, independent of period_ticks
    let deadline_cntvct = start_cntvct.wrapping_add(hard_timeout_ticks);
    loop {
        let now_count = crate::entry::aarch64::TICK_COUNT.load(AOrdering::Acquire);
        if now_count >= target { break; }
        if ARCH.now_ticks() >= deadline_cntvct { break; }
        ARCH.wfi();
    }
    let ticks_after = crate::entry::aarch64::TICK_COUNT.load(AOrdering::Acquire);
    let elapsed_cntvct = ARCH.now_ticks().wrapping_sub(start_cntvct);
    let elapsed_ms = if live_hz == 0 { 0 } else { elapsed_cntvct * 1000 / live_hz };
    // Generous 4x-either-way band around EXPECTED_MS: wide enough to
    // absorb QEMU scheduling jitter and the self-test/kprintln! work
    // already done above, tight enough that a 16x frequency mixup or a
    // re-arm-after-EOI storm (2x too fast — see `handle_irq`'s own
    // comment on ordering) still falls outside it.
    if ticks_after < target {
        azos_drv_sys::kerr!("[TIMER] FAILED: only {} of {} ticks arrived in {} ms (expected ~{} ms)",
            ticks_after - ticks_before, TICK_TARGET, elapsed_ms, EXPECTED_MS);
    } else if elapsed_ms < EXPECTED_MS / 4 || elapsed_ms > EXPECTED_MS * 4 {
        azos_drv_sys::kerr!("[TIMER] FAILED: {} ticks arrived in {} ms, expected ~{} ms \
                   (period computed wrong, or re-arming too fast/slow)",
            ticks_after - ticks_before, elapsed_ms, EXPECTED_MS);
    } else {
        kprintln!("[TIMER] ticks: {} in {} ms (target {}, expected ~{} ms)",
            ticks_after - ticks_before, elapsed_ms, TICK_TARGET, EXPECTED_MS);
    }

    // ── (c) FP/SIMD survives interrupt ────────────────────────────────
    let probe_target = ticks_after + TICK_TARGET;
    let probe_deadline = ARCH.now_ticks().wrapping_add(live_hz.saturating_mul(2));
    let (v8_lo, v8_hi, _probe_final_ticks) =
        crate::entry::aarch64::fp_survives_interrupt_probe(probe_target, probe_deadline);
    let pattern = crate::entry::aarch64::FP_PROBE_PATTERN;
    if v8_lo == pattern && v8_hi == pattern {
        kprintln!("[TRAP] FP/SIMD survives interrupt: PASS (v8=[{:#x},{:#x}])", v8_hi, v8_lo);
    } else {
        azos_drv_sys::kerr!("[TRAP] FAILED: FP/SIMD did not survive interrupt — v8=[{:#x},{:#x}], \
                   expected [{:#x},{:#x}]", v8_hi, v8_lo, pattern, pattern);
    }

    // ── IRQ-stack proof (task 1) ───────────────────────────────────────
    let (probed, took_own_stack) = crate::entry::aarch64::irq_stack_probe_result();
    if probed && took_own_stack {
        kprintln!("[AARCH64-IRQSTACK] hart 0 handles interrupts on its own stack");
    } else if probed {
        azos_drv_sys::kerr!("[AARCH64-IRQSTACK] FAILED: hart 0 handled an interrupt off its own IRQ stack");
    } else {
        azos_drv_sys::kerr!("[AARCH64-IRQSTACK] FAILED: no interrupt was observed to probe");
    }
    if !crate::aarch64_irq_stack_intact() {
        azos_drv_sys::kerr!("[AARCH64-IRQSTACK] FAILED: hart 0's IRQ-stack magic word was \
                   overwritten (overflow)");
    }

    // ── TTBR1 alias proof (aarch64 parity program, TTBR1 migration) ────
    //
    // `aarch64_early_ttbr1_alias` (boot.S, right after
    // `aarch64_early_mmu_init`) already built the alias table and
    // turned TTBR1 walks on; this reads back what the hardware
    // actually latched, decodes T0SZ/T1SZ from the LIVE TCR_EL1 (not
    // the constants that requested them), and does a live
    // cross-mapping read to prove the table itself resolves to the
    // right physical page. See `azos_arch::mmu_setup::
    // enable_ttbr1_alias`'s doc for what this does and does not
    // change about the kernel's actual translations.
    let ttbr1_boot = azos_arch::mmu_setup::TTBR1_BOOT_VALUE.load(AOrdering::Acquire);
    let tcr_boot = azos_arch::mmu_setup::TCR_BOOT_VALUE.load(AOrdering::Acquire);
    let t0sz = azos_arch::mmu::tcr_t0sz(tcr_boot);
    let t1sz = azos_arch::mmu::tcr_t1sz(tcr_boot);
    let ttbr1_now = azos_arch::sysregs::read_ttbr1_el1();
    let (canary_low, canary_high, canary_match) = crate::entry::aarch64::ttbr1_alias_verify();
    kprintln!("[AARCH64-TTBR1] T0SZ={} T1SZ={} TTBR1_EL1={:#x} \
               KERNEL_VA_OFFSET={:#x}",
        t0sz, t1sz, ttbr1_boot, azos_arch::mmu::KERNEL_VA_OFFSET);
    // 25 (39-bit halves) at a 4 or 16 KiB granule, 16 (48-bit) at 64 KiB:
    // the input range this build's granule walks in three levels.
    let want_tsz = azos_arch::mmu::GRANULE.tsz();
    if t0sz != want_tsz || t1sz != want_tsz {
        azos_drv_sys::kerr!("[AARCH64-TTBR1] FAILED: expected T0SZ=T1SZ={} ({}-bit \
                   halves), read T0SZ={} T1SZ={}", want_tsz, 64 - want_tsz, t0sz, t1sz);
    } else if ttbr1_boot == 0 {
        azos_drv_sys::kerr!("[AARCH64-TTBR1] FAILED: TTBR1_EL1 read back 0 — \
                   enable_ttbr1_alias did not run or did not publish it");
    } else if !canary_match {
        azos_drv_sys::kerr!("[AARCH64-TTBR1] FAILED: alias read mismatch — low={:#x} \
                   high={:#x}, expected both == {:#x}",
            canary_low, canary_high, crate::entry::aarch64::TTBR1_ALIAS_CANARY);
    } else if ttbr1_now as usize & !0xFFF != azos_mm::vmm::kernel_pagetable() {
        // The boot alias is SUPPOSED to be gone by now: `enable_paging`
        // replaces it with the kernel's real table, which is what carries
        // W^X, NX and the stack guards. A TTBR1 still holding the alias
        // means the kernel is executing out of a flat 1 GiB mapping with
        // none of those permissions — the exact silent hole this
        // migration exists to close, and the shape an earlier attempt
        // shipped before the guard-page probe caught it.
        azos_drv_sys::kerr!("[AARCH64-TTBR1] FAILED: TTBR1_EL1 is not the kernel page table — \
                   kernel PT {:#x}, TTBR1 {:#x} (boot alias was {:#x})",
                  azos_mm::vmm::kernel_pagetable(), ttbr1_now, ttbr1_boot);
    } else {
        kprintln!("[AARCH64-TTBR1] kernel runs in the upper half: alias low={:#x} \
                   high={:#x} match, TTBR1_EL1 = kernel PT {:#x}",
                  canary_low, canary_high, ttbr1_now);
    }

    // ── Translation granule readback (config/Kconfig.arch AARCH64_PAGE_*) ──
    //
    // Decoded from the LIVE TCR_EL1, not from the constants that asked for
    // it: TG0 (bits [15:14]) and TG1 ([31:30]) use different encodings, so
    // each is decoded on its own and both must name the granule this
    // kernel was built for. The table count is a walk of the kernel's own
    // page table (root + every table under it), so the line also says
    // what the granule costs in page-table memory on this boot.
    {
        let tcr = azos_arch::sysregs::read_tcr_el1();
        let tg0_kib = match (tcr >> 14) & 0b11 { 0b00 => 4, 0b10 => 16, 0b01 => 64, _ => 0 };
        let tg1_kib = match (tcr >> 30) & 0b11 { 0b10 => 4, 0b01 => 16, 0b11 => 64, _ => 0 };
        let g = azos_arch::mmu::GRANULE;
        let want_kib = g.page_size() / 1024;
        let kpt = azos_mm::vmm::kernel_pagetable();
        let tables = azos_mm::vmm::table_frames(kpt);
        let verdict = if tg0_kib == want_kib && tg1_kib == want_kib { "ok" } else { "MISMATCH" };
        kprintln!("[AARCH64-GRANULE] {}: TG0={} KiB TG1={} KiB (built for {} KiB), \
                   T0SZ={} T1SZ={}, root {} entries, level-1 block {} KiB; \
                   kernel page tables: {} frames = {} KiB",
            verdict, tg0_kib, tg1_kib, want_kib,
            azos_arch::mmu::tcr_t0sz(tcr), azos_arch::mmu::tcr_t1sz(tcr),
            g.root_entries(), g.level_size(1) / 1024,
            tables, tables * g.page_size() / 1024);
    }

    // ── M41 (coordinator / U10-7, audit): TCR_EL1.IPS/AS readback ────
    //
    // MARKER, per-boot proof that `tcr_value_for_this_cpu` actually
    // landed what it computed, not just that the constant looks right
    // in source. Read from the LIVE register (not `tcr_boot`, which is
    // the alias-time snapshot from before `enable_paging` — IPS/AS do
    // not change across that switch, but this line is meant to prove
    // the CURRENT state, the same discipline every other readback in
    // this block follows).
    let tcr_live = azos_arch::sysregs::read_tcr_el1();
    let ips = azos_arch::mmu::tcr_ips(tcr_live);
    let as_bit = azos_arch::mmu::tcr_as(tcr_live);
    kprintln!("[AARCH64-TCR] IPS={} AS={}", ips, as_bit);
    // Both FAILED branches are QEMU-target claims (`-cpu max`/cortex-a72
    // report PARange >= 4 and 16-bit ASID support), not an architectural
    // guarantee for every CPU this crate might run on: a real
    // implementation that only supports 8-bit ASIDs makes `AS` RES0 —
    // reading back 0 there would be correct hardware behavior, not this
    // code failing to ask. This gate boots QEMU only, so it is a fair
    // canary here; it is not a portable assertion if reused elsewhere.
    if ips == 0 {
        azos_drv_sys::kerr!("[AARCH64-TCR] FAILED: IPS=0 — TCR_EL1 still describes \
                   32-bit physical addresses only");
    }
    if as_bit == 0 {
        azos_drv_sys::kerr!("[AARCH64-TCR] FAILED: AS=0 on QEMU — TCR_EL1 still \
                   selects an 8-bit ASID");
    }
}

/// `a * a + b` on the FP unit, operands and result as raw f64 bits.
///
/// Boot-only (called from `kernel_main`'s early self-check, before any user
/// task exists), so clobbering d0/d1 cannot destroy anyone's FP state. Named
/// in `tools/aarch64_fp_free_check.sh`'s allowed list — the one place kernel
/// code outside the user-FP save/restore executes an FP instruction.
#[inline(never)]
pub(crate) fn fp_self_check(a_bits: u64, b_bits: u64) -> u64 {
    let out: u64;
    unsafe {
        core::arch::asm!(
            ".arch_extension fp",
            "fmov d0, {a}",
            "fmov d1, {b}",
            "fmul d0, d0, d0",
            "fadd d0, d0, d1",
            "fmov {out}, d0",
            a = in(reg) a_bits,
            b = in(reg) b_bits,
            out = lateout(reg) out,
            options(nomem, nostack),
        );
    }
    out
}
