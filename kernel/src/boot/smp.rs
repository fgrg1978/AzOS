// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The secondary-CPU Rust entry, one for every ISA (called from `boot.S`).
//!
//! The skeleton is shared; what differs per ISA is an [`ArchEntry`] hook
//! (`kernel/src/entry/<isa>/arch_entry.rs`), named for the step it performs.
//! Divergences that used to hide in two copies of this function, and where
//! each one went:
//!
//! * the "not a possible CPU" park ran on riscv64 only; it now runs on both
//!   (aarch64's boot.S parks a PE with no stack, but a PE inside the stack
//!   table and outside the possible mask reached the scheduler);
//! * riscv64 notes the hart in the TLB shootdown's scan set, x86_64 also
//!   publishes the CR3 it runs on (a CPU that only runs kernel tasks never
//!   writes CR3, and a kernel-wide shootdown must still name it), aarch64
//!   does nothing (broadcast `TLBI ...IS`): [`ArchEntry::secondary_tlb_online`],
//!   after the interrupt controller's step, so a shootdown that names the CPU
//!   from then on is taken when it unmasks;
//! * riscv64 rewrites `tp` on every idle iteration, aarch64 did not: both do
//!   now (`set_percpu_base`, one register write per wake of a loop that only
//!   runs until the first dispatch);
//! * aarch64 published `CORE_ONLINE` AFTER unmasking interrupts, so a tick
//!   taken in between dispatched this core's idle task and the store never
//!   ran: publication now precedes `enable_all` on both. A wake sent in that
//!   window stays pending and is taken at `enable_all`.
//!
//! The boot CPU's half of SMP lives here too: [`install_topology`] works out
//! which CPUs share a core, a cluster, a cache, a node and a package.

use crate::*;
use azos_arch::{ArchEntry, Cpu, Interrupts, ARCH};
use azos_sched::topo::{self, CpuRaw, Level};

// The DT parser's "not named" is the topology's.
#[cfg(not(target_arch = "x86_64"))]
const _: () = assert!(azos_dtb::DT_TOPO_NONE == topo::NONE);
// Masks are one word.
const _: () = assert!(azos_limits::NR_CPUS <= topo::MAX_CPUS);

/// Secondary-CPU entry point, the ONE symbol both `boot.S` files call once
/// this CPU has a stack, its trap vector and (aarch64) its MMU. Never
/// returns: the first tick on this CPU reaches `schedule()` with no current
/// task, which dispatches the idle task `kernel_main` pinned here, and this
/// raw loop is never re-entered after that first dispatch.
#[unsafe(no_mangle)]
pub extern "C" fn secondary_main(hart_id: usize) -> ! {
    // boot.S already put the per-CPU base (the hart id) in place; set it
    // again in case an early Rust call clobbered it (riscv64's `tp` is an
    // ordinary register to the ABI).
    ARCH.set_percpu_base(hart_id);

    // boot.S range-checked us against MAX_HARTS (Kconfig `NR_CPUS`), which
    // guards the stack and trap-vector slots. A CPU below that ceiling but
    // outside the possible mask (above the firmware's count) has no per-CPU
    // area, and `wake_secondaries` never starts one — but a CPU can arrive
    // here without us starting it (firmware state, a resumed CPU, a future
    // warm-boot path). Park it before it enables the timer: one tick later
    // it would be inside `schedule()` reaching for an area it does not have.
    // Interrupts are still masked (boot.S), so parking here is final.
    if !azos_percpu::cpu_possible(hart_id) {
        kprintln!("[SMP] hart {} is not a possible CPU (nr_cpu_ids {}) — parking (no per-CPU area)",
                  hart_id, azos_percpu::nr_cpu_ids());
        loop { ARCH.wait_for_interrupt(); }
    }
    secondary_hw_init(hart_id);

    ARCH.enable_all();

    // The first tick calls `schedule()`, which picks the tasks `kernel_main`
    // assigned to this CPU. The per-CPU base is re-set on every iteration:
    // on riscv64 SBI calls and Rust code in the timer ISR may use `tp` as a
    // scratch register, and the tick must find it equal to the hart id for
    // `current_cpu_id()`.
    loop {
        ARCH.set_percpu_base(hart_id);
        ARCH.wait_for_interrupt();
    }
}

/// The per-CPU hardware steps of a CPU that comes up: the interrupt
/// controller's per-CPU state, the TLB shootdown scan, the first tick, and the
/// online publication. The cold start (`secondary_main`) and a CPU that comes back
/// through the saved-context path (`entry/<isa>/resume.rs`: a hotplug stop, a
/// power-down idle state) both run them: that path keeps the registers and
/// the stack, not what the controller and the timer held.
pub(crate) fn secondary_hw_init(hart_id: usize) {
    ARCH.set_percpu_base(hart_id);
    ARCH_ENTRY.secondary_irq_init(hart_id);
    ARCH_ENTRY.secondary_tlb_online(hart_id);
    ARCH_ENTRY.secondary_timer_init(hart_id);
    ARCH_ENTRY.secondary_publish_online(hart_id);
}

/// The logical CPU of this boot that a device-tree `cpu` node's `reg` names,
/// `None` for a node that is none (disabled, past `NR_CPUS`): `reg` is the
/// hart id on riscv64 and the MPIDR on aarch64, keyed as `azos_percpu` maps
/// it. x86_64 has no device tree; there the value is taken as the APIC id.
/// Readers: `firmware_labels` (riscv64, aarch64) and the energy model.
#[cfg(any(feature = "energy", not(target_arch = "x86_64")))]
pub(crate) fn cpu_of_dt_reg(reg: u64) -> Option<usize> {
    #[cfg(not(target_arch = "aarch64"))]
    let hw = reg as usize;
    #[cfg(target_arch = "aarch64")]
    let hw = azos_arch::cpu::mpidr_affinity_key(reg) as usize;
    azos_percpu::cpu_of_hw(hw)
}

/// What the device tree says about CPUs `0..n`: each `cpu` node's `reg` is the
/// hardware id (riscv64: the hart id; aarch64: the MPIDR affinity) of the
/// logical CPU `azos_percpu` maps it to; a node that is no CPU of this boot
/// (the JH7110's disabled S7, one past `NR_CPUS`) labels nothing.
#[cfg(not(target_arch = "x86_64"))]
fn firmware_labels(n: usize, dtb_ptr: usize, raw: &mut [CpuRaw]) -> topo::Source {
    if dtb_ptr == 0 {
        return topo::Source::None;
    }
    // SAFETY: `dtb_ptr` is the firmware's blob, mapped and bounds-checked by
    // the parser (the precondition of every `azos_dtb` entry).
    let Some(dt) = (unsafe { azos_dtb::dtb_cpu_topology(azos_mm::addr::phys_to_virt(dtb_ptr) as *const u8) }) else {
        return topo::Source::None;
    };
    let mut stated = dt.has_cpu_map;
    for c in dt.cpus() {
        let Some(cpu) = cpu_of_dt_reg(c.reg) else { continue };
        if cpu < n {
            raw[cpu] = CpuRaw {
                core: c.core,
                cluster: c.cluster,
                llc: topo::NONE,
                node: topo::NONE,
                package: c.socket,
                dmips: c.capacity_dmips_mhz,
            };
            stated |= c.capacity_dmips_mhz != 0;
        }
    }
    if stated { topo::Source::Dt } else { topo::Source::None }
}

// arch-only: x86 names its CPUs from the ACPI MADT.
#[cfg(target_arch = "x86_64")]
use crate::entry::x86_64::smp::firmware_labels;

/// Groups shown per level in the boot line.
const SHOWN_GROUPS: usize = 4;

/// Build the topology of the `num_cpus` CPUs from what the firmware says
/// (device tree, ACPI PPTT, CPUID), install it for the balancer and the energy
/// model, and print it. Boot CPU, once the CPU count is known and before the
/// scheduler starts.
pub(crate) fn install_topology(num_cpus: usize, dtb_ptr: usize) {
    let n = num_cpus.min(topo::MAX_CPUS);
    let mut raw = [CpuRaw::UNKNOWN; topo::MAX_CPUS];
    let source = firmware_labels(n, dtb_ptr, &mut raw);
    topo::install(&topo::build(&raw[..n], source));

    kprintln!("[TOPO] {} CPU(s) from {}", topo::installed(), topo::source().name());
    for level in Level::ALL {
        let (groups, lo, hi) = topo::summary(level);
        // The first few groups, each named by its CPUs (a mask in hex).
        let mut shown = [0u64; SHOWN_GROUPS];
        let mut k = 0;
        for cpu in 0..topo::installed() {
            let m = topo::mask(level, cpu);
            if m.trailing_zeros() as usize == cpu && k < SHOWN_GROUPS {
                shown[k] = m;
                k += 1;
            }
        }
        let more = if groups > k { " ..." } else { "" };
        if lo == hi {
            kprintln!("[TOPO] {:<7} {} x {}: {:x?}{}", level.name(), groups, lo, &shown[..k], more);
        } else {
            kprintln!("[TOPO] {:<7} {} groups of {}..{}: {:x?}{}", level.name(), groups, lo, hi, &shown[..k], more);
        }
    }
    if topo::capacity_known() {
        let caps = || (0..topo::installed()).map(topo::capacity);
        kprintln!("[TOPO] capacity {}..{} of {}", caps().min().unwrap_or(0), caps().max().unwrap_or(0),
            topo::CAPACITY_SCALE);
    } else {
        kprintln!("[TOPO] capacity {} on every CPU (not stated)", topo::CAPACITY_SCALE);
    }
    if topo::irregular() {
        azos_drv_sys::kwarn!("[TOPO] the firmware's levels do not nest: groups merged until each holds the one inside it");
    }
}
