// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 secondary CPUs: `_secondary_start` (asm/ap_entry.S) and the boot
//! CPU's bring-up check, as `entry/aarch64/smp.rs` does after PSCI. Each AP
//! is started by `azos_sched::smp::wake_harts` -> `Boot::hart_start`
//! (INIT-SIPI-SIPI, `azos_arch::smp`).

use core::sync::atomic::Ordering;

use azos_drv_sys::kprintln;

use super::irq::{CORE_ONLINE, IPI_RECEIVED, TICK_PER_HART};

core::arch::global_asm!(
    include_str!("asm/ap_entry.S"),
    max_harts = const crate::MAX_HARTS,
    dmb = const azos_arch::mmu::DIRECT_MAP_BASE,
    options(att_syntax)
);

/// The Rust half of `_secondary_start`: this CPU's own GDT + TSS (IST), the
/// shared IDT, its GS-relative per-CPU area, the `syscall` MSRs and FP
/// state (`cpu_init::init_cpu`), then its paging registers (PAT, WP, PGE,
/// PCIDE) and SMEP/SMAP as the boot CPU chose them, before the common
/// `secondary_main`. Interrupts are off throughout.
#[unsafe(no_mangle)]
pub extern "C" fn x86_64_secondary_entry(cpu: usize) -> ! {
    super::cpu_init::init_cpu(cpu);
    let caps = crate::boot_hooks::paging_caps();
    let _ = azos_arch::mmu::cpu::setup_paging_regs(&caps);
    let _ = azos_arch::mmu::cpu::enable_access_protection(&caps);
    crate::boot::smp::secondary_main(cpu)
}

/// Ticks a secondary must take before it counts as running its timer.
const MIN_TICKS: u64 = 3;

/// The clock value `s` seconds from now.
fn deadline_s(s: u64) -> u64 {
    use azos_arch::{Cpu, ARCH};
    ARCH.now_ticks().wrapping_add(azos_arch::timer::TICK_HZ.saturating_mul(s))
}

fn wait_until(deadline: u64, done: impl Fn() -> bool) -> bool {
    use azos_arch::{Cpu, ARCH};
    while !done() {
        if ARCH.now_ticks() >= deadline {
            return false;
        }
        ARCH.wfi();
    }
    true
}

pub(crate) fn wake_secondaries(num_cpus: usize) {
    azos_drv_sys::uart::enable_smp_lock();
    kprintln!("[SMP] UART lock enabled");
    kprintln!("[SMP] Starting {} secondary CPU(s) via INIT-SIPI-SIPI...", num_cpus.saturating_sub(1));
    // SAFETY: boot CPU, once, after the per-CPU areas and stacks exist.
    let online = unsafe { azos_sched::smp::wake_harts(num_cpus) };
    if online != num_cpus {
        azos_drv_sys::kwarn!("[SMP] WARNING: only {}/{} CPUs started — degraded to {} online CPU(s)",
            online, num_cpus, online);
    }
    azos_sched::smp::NUM_ONLINE_CPUS.store(online, Ordering::SeqCst);
    if online < azos_sched::MAX_CPUS {
        let rescued = azos_sched::rebalance_from_offline_cpus(online, num_cpus);
        if rescued != 0 {
            kprintln!("[SMP] rescued {} task(s) off CPUs that never came up", rescued);
        }
    }

    let p = azos_arch::platform_impl::platform();
    for cpu in 1..online {
        if !wait_until(deadline_s(2), || CORE_ONLINE[cpu].load(Ordering::Acquire)) {
            azos_drv_sys::kerr!("[SMP] FAILED: CPU {} never published online", cpu);
            continue;
        }
        kprintln!("[SMP] CPU {} online: APIC ID {}", cpu, p.apic_ids[cpu]);
        let ticked = wait_until(deadline_s(2), || TICK_PER_HART[cpu].load(Ordering::Acquire) >= MIN_TICKS);
        let ticks = TICK_PER_HART[cpu].load(Ordering::Acquire);
        if ticked {
            kprintln!("[SMP] CPU {} took {} ticks (>= {})", cpu, ticks, MIN_TICKS);
        } else {
            azos_drv_sys::kerr!("[SMP] FAILED: CPU {} took only {} tick(s), expected >= {}", cpu, ticks, MIN_TICKS);
        }
    }

    if online > 1 {
        use azos_arch::{Interrupts, ARCH};
        let target = 1usize;
        let before = IPI_RECEIVED[target].load(Ordering::Acquire);
        kprintln!("[IPI] CPU 0 sending the reschedule IPI to CPU {}...", target);
        ARCH.send_ipi(target);
        if wait_until(deadline_s(2), || IPI_RECEIVED[target].load(Ordering::Acquire) > before) {
            kprintln!("[IPI] sent by CPU 0, received by CPU {}: count={}",
                target, IPI_RECEIVED[target].load(Ordering::Acquire));
        } else {
            azos_drv_sys::kerr!("[IPI] FAILED: CPU {} never took the reschedule IPI", target);
        }
    }
}
