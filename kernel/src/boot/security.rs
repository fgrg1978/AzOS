// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `kernel_main`'s Phases D and 16: the boot-loop crash counter, the riscv64
//! PMP policy printed for the boot-time audit, and the stack canary and
//! system watchdog lines.

use crate::*;

/// Phases D and 16, in order (see the module doc). `early` is read on
/// riscv64 only (`EarlyBoot`'s doc). Inlined, as every boot phase (see
/// `boot`'s module doc).
#[inline(always)]
#[cfg_attr(not(target_arch = "riscv64"), allow(unused_variables))]
pub(crate) fn report_security(early: &EarlyBoot) {
    // Read only by the riscv64-only PMP audit block further down (the one
    // block in this shared body that still names `pmp::pmp_regions`
    // directly) — see `EarlyBoot`'s own doc.
    #[cfg(target_arch = "riscv64")]
    let heap_start = early.heap_start;
    #[cfg(target_arch = "riscv64")]
    let kernel_end_aligned = early.kernel_end_aligned;

    // ---- Phase D: PMP Security + Hardware Watchdog ----

    kprintln!("========================================");
    kprintln!(" Phase D: PMP Security + HW Watchdog");
    kprintln!("========================================");

    // F11.3: Check crash counter — detect boot loops.
    // The counter holds the consecutive unconfirmed boots read from
    // BOOTMETA's `boot_count` (`boot_count_loaded`). It is NOT cleared here:
    // a boot counts as clean only once `ota_mark_boot_good` runs (sys-wdt,
    // after `OTA_BOOT_GOOD_DELAY_S` of uptime), which clears both copies.
    {
        let prev_crashes = azos_drv_sys::wdt::crash_counter_get();
        if prev_crashes >= 3 {
            azos_drv_sys::kwarn!("[WDT] WARNING: {} consecutive crashes detected (boot loop?)", prev_crashes);
            azos_drv_sys::kwarn!("[WDT] The [OTA] and [RECOVERY] lines above say what this boot does about it \
                       (rollback, or safe mode: {}).",
                      azos_actuation::estop::safe_mode_active());
        } else if prev_crashes > 0 {
            kprintln!("[WDT] Recovering from {} previous crash(es)", prev_crashes);
        }
        kprintln!("[WDT] Crash counter clears when OTA marks this boot good ({} s)",
            azos_ota::OTA_BOOT_GOOD_DELAY_S);
    }

    // PMP: display the intended AzOS memory-protection policy.
    // pmp_configure() must be called from M-mode (before mret into S-mode).
    // Here we display it for boot-time audit; actual enforcement is M-mode only.
    // riscv64-only: PMP (Physical Memory Protection) is a RISC-V privileged-
    // spec mechanism with no aarch64 equivalent — `azos_arch::ext::pmp` does
    // not exist as a module on that ISA (observed: E0432 "no `pmp` in the
    // root" on an aarch64 build before this gate was added, kernel-main-
    // merge task). Reads `heap_start`/`kernel_end_aligned` off `EarlyBoot`
    // — see that struct's own doc for why those two fields exist.
    #[cfg(target_arch = "riscv64")]
    {
        use azos_arch::ext::pmp;
        let fw_end = azos_drv_base::platform::hw::KERNEL_LOAD; // end of OpenSBI
        // PMP is a PHYSICAL policy: the image's end is its frame's, not the
        // slid VA a KASLR boot runs it at (`heap_start` is already physical).
        let regions = pmp::pmp_regions(fw_end, azos_mm::addr::virt_to_phys(kernel_end_aligned), heap_start, HEAP_SIZE);
        kprintln!("[PMP] Memory-protection policy ({} TOR regions):", pmp::N_PMP_REGIONS);
        kprintln!("[PMP]   Note: CSRs are M-mode only; configure from boot stub.");
        for r in &regions {
            kprintln!("[PMP]   {:20}  base={:#010x}  size={:#010x}  {}{}{}",
                r.name,
                r.base, r.size,
                if r.perm.r { "R" } else { "-" },
                if r.perm.w { "W" } else { "-" },
                if r.perm.x { "X" } else { "-" });
        }
    }
    kprintln!();

    // ---- Phase 16: Security — stack canaries + system watchdog ----

    kprintln!("========================================");
    kprintln!(" Phase 16: Security");
    kprintln!("========================================");
    kprintln!("[SEC] Stack canary: {}, fingerprint {:06x} — {}",
        if azos_sched::scheduler::stack_canary() == azos_sched::STACK_CANARY {
            "fixed (pool unseeded)"
        } else {
            "from the entropy pool"
        },
        azos_sched::scheduler::stack_canary_fingerprint(),
        if azos_sched::scheduler::stack_guard_pages_active() {
            "not written: stack guard pages active"
        } else {
            "written at each task_create"
        });
    kprintln!("[SEC] System watchdog: monitors canaries + timer liveness every ~1 s");
    kprintln!();
}
