// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 secondary CPUs: `_secondary_start` (asm/ap_entry.S) and the boot
//! CPU's bring-up check, as `entry/aarch64/smp.rs` does after PSCI. Each AP
//! is started by `azos_sched::smp::wake_harts` -> `Boot::hart_start`
//! (INIT-SIPI-SIPI, `azos_arch::smp`).

use core::sync::atomic::{AtomicU32, Ordering};

use azos_drv_sys::kprintln;
use azos_sched::topo::{self, CpuRaw, Source};

use super::irq::{CORE_ONLINE, IPI_RECEIVED, TICK_PER_HART};

core::arch::global_asm!(
    include_str!("asm/ap_entry.S"),
    max_harts = const crate::MAX_HARTS,
    dmb = const azos_arch::mmu::DIRECT_MAP_BASE,
    options(att_syntax)
);

/// What the firmware says about CPUs `0..n` on x86_64: the ACPI PPTT when it
/// lists every one of them (by the ACPI processor id the MADT gives its APIC
/// id), else CPUID, decoded once here and applied to each CPU's APIC id.
pub(crate) fn firmware_labels(n: usize, _dtb_ptr: usize, raw: &mut [CpuRaw]) -> Source {
    use azos_arch::platform_impl::{cpuid, platform};
    let p = platform();
    let n = n.min(p.n_cpus);
    if let (Some(pptt), Some(madt)) = (p.acpi.pptt.as_ref(), p.madt()) {
        let listed = |i: usize| {
            let uid = madt.cpus().iter().find(|c| c.apic_id == p.apic_ids[i])?.uid;
            pptt.for_uid(uid)
        };
        if (0..n).all(|i| listed(i).is_some()) {
            for i in 0..n {
                if let Some(c) = listed(i) {
                    raw[i] = CpuRaw {
                        core: c.core,
                        cluster: c.cluster,
                        llc: c.llc,
                        node: topo::NONE,
                        package: c.package,
                        dmips: 0,
                    };
                }
            }
            return Source::Pptt;
        }
    }
    let shape = topo::cpuid_shape(cpuid);
    if shape == topo::CpuidShape::NONE {
        return Source::None;
    }
    for i in 0..n {
        raw[i] = shape.ids(p.apic_ids[i], 0);
    }
    Source::Cpuid
}

/// The Rust half of `_secondary_start`: this CPU's own GDT + TSS (IST), the
/// shared IDT, its GS-relative per-CPU area, the `syscall` MSRs and FP
/// state (`cpu_init::init_cpu`), then its paging registers (PAT, WP, PGE,
/// PCIDE) and SMEP/SMAP as the boot CPU chose them, before the common
/// `secondary_main`. Interrupts are off throughout.
#[unsafe(no_mangle)]
pub extern "C" fn x86_64_secondary_entry(cpu: usize) -> ! {
    super::ext::cpu_init::init_cpu(cpu);
    // Kconfig X86_UCODE_LOAD: the boot CPU's patch, before this CPU's CPUID
    // is read for its core type and before its mitigation MSRs below.
    super::ext::ucode::this_cpu(cpu);
    // CPUID answers for the CPU that runs it: this CPU's core type, for the
    // energy model the boot CPU makes once every CPU has recorded. Held here,
    // interrupts off, until it has installed it: no CPU enters the scheduler
    // before the model is in place (`azos_sched::energy::install`'s contract).
    #[cfg(feature = "energy")]
    {
        azos_arch::ext::hybrid::record_this_cpu(cpu);
        while !ENERGY_RELEASE.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
    }
    let caps = crate::boot_hooks::paging_caps();
    let _ = azos_arch::mmu::cpu::setup_paging_regs(&caps);
    let st = azos_arch::mmu::cpu::enable_access_protection(&caps);
    // Kconfig X86_CET_IBT: CR4.CET and IA32_S_CET are per CPU.
    let ibt = crate::boot_hooks::enable_ibt();
    // MSR_TEST_CTRL is per core (Kconfig X86_SPLIT_LOCK); a no-op unless the boot CPU wanted it.
    let split_lock = azos_arch::ext::splitlock::enable_this_cpu();
    // Every CPU must run as the boot CPU chose (K1 L1): `trap_entry.S`'s
    // `clac` follows the boot CPU's SMAP (`X86_64_SMAP_ON` is global), so a
    // CPU without it takes #UD at its first trap, and one whose SMEP, SMAP or
    // IBT did not take runs unprotected. Named here, before this CPU takes any
    // trap. Not parked: `wake_harts` counted it online already, so a parked
    // CPU would strand the tasks queued on it; the FAILED line is the report.
    let mine = protection(&st, ibt, split_lock);
    let boot = BOOT_PROTECTION.load(Ordering::Acquire);
    if mine != boot {
        azos_drv_sys::kerr!("[SMP] FAILED: CPU {} runs protection {:#x}, the boot CPU {:#x} \
            (bits: NXE WP PGE PCIDE SMEP SMAP UMIP IBT SPLIT-LOCK)", cpu, mine, boot);
    }
    // IA32_SPEC_CTRL, EFER.AIBRS, DE_CFG, MCU_OPT_CTRL are per CPU (Kconfig
    // X86_MIT_*); the boot CPU decided, each CPU writes its own.
    azos_arch::ext::mitigations::apply_this_cpu();
    // A CPU taken offline (CPU hotplug) left its context in a slot: it goes
    // back to it, on its own tables as just loaded. A first start has none.
    if super::resume::WANTED {
        let area = azos_arch::smp::resume_area(cpu);
        if !area.is_null() {
            // SAFETY: the slot `resume_area` handed over, saved by this CPU.
            unsafe { super::resume::azos_cpu_resume_restore(area) }
        }
    }
    crate::boot::smp::secondary_main(cpu)
}

/// The boot CPU has installed the energy model (or decided there is none):
/// the secondaries may go on. Set once, by `wake_secondaries`, whatever the
/// model; a CPU that comes up later (hotplug) finds it set.
#[cfg(feature = "energy")]
static ENERGY_RELEASE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Wait up to `s` seconds for `done`, polling: this is the window in which a
/// started secondary records its core type, a few microseconds in practice.
#[cfg(feature = "energy")]
fn poll_until(s: u64, done: impl Fn() -> bool) -> bool {
    use azos_arch::{Cpu, ARCH};
    let deadline = deadline_s(s);
    while !done() {
        if ARCH.now_ticks() >= deadline {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

/// The boot CPU's [`protection`], published by [`wake_secondaries`] before
/// any secondary starts: what each one must match.
static BOOT_PROTECTION: AtomicU32 = AtomicU32::new(0);

/// A CPU's paging and protection readback, one bit each: what a secondary
/// compares with the boot CPU's.
fn protection(st: &azos_arch::mmu::PagingState, ibt: bool, split_lock: bool) -> u32 {
    [st.nxe, st.wp, st.pge, st.pcide, st.smep, st.smap, st.umip, ibt, split_lock]
        .iter()
        .enumerate()
        .fold(0, |w, (i, &on)| w | (on as u32) << i)
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
    BOOT_PROTECTION.store(
        protection(&azos_arch::mmu::cpu::state(), crate::boot_hooks::ibt_on(),
                   azos_arch::ext::splitlock::active_this_cpu()),
        Ordering::Release);

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

    // The started secondaries record their core type and wait in their entry;
    // the energy model is installed, then they go on (`ENERGY_RELEASE`). A
    // secondary that never records is named, and the model refuses it.
    #[cfg(feature = "energy")]
    {
        for cpu in 1..online {
            if !poll_until(2, || azos_arch::ext::hybrid::recorded(cpu).is_some()) {
                azos_drv_sys::kerr!("[SMP] CPU {} started but never recorded its core type", cpu);
            }
        }
        crate::boot::install_energy_after_smp(num_cpus, online);
        ENERGY_RELEASE.store(true, Ordering::Release);
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
