// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The core types the x86_64 CPUs report (CPUID leaves 0x1A and 0x80000026),
//! as the scheduler's core classes and its energy model (`boot::energy`) read
//! them. The reading is `azos_arch::ext::hybrid`; shared boot code reaches it
//! only through these calls, so it names no ISA-specific arch module.

use azos_arch::ext::hybrid::{recorded, CoreKind, MAX_RECORDED};
use azos_energy::model::{CoreClass, MAX_MODEL_CPUS};

const _: () = assert!(MAX_RECORDED == MAX_MODEL_CPUS);

/// Every CPU has recorded: the scheduler's core classes and capacities follow,
/// with or without an energy model. The performance cores are class 0; a kind
/// the CPU does not name counts as the small class, so no budget is ever
/// admitted on it as if it were big.
pub(crate) fn install_core_classes(online: usize) {
    use azos_energy::model::CPUID_EFFICIENCY_CAPACITY;
    use azos_sched::topo;
    if (0..online).any(|c| recorded_class(c).is_none()) {
        azos_drv_sys::kwarn!("[TOPO] a CPU recorded no core type: every CPU counts as equal");
        return;
    }
    let small = |c: usize| !matches!(recorded_class(c), Some(CoreClass::Uniform | CoreClass::Performance));
    let flat = canary!("asym-capacity-flat");
    topo::install_core_types(
        |c| small(c) as u8,
        |c| if small(c) && !flat { CPUID_EFFICIENCY_CAPACITY } else { topo::CAPACITY_SCALE },
    );
    if topo::differs() {
        crate::boot::smp::report_core_classes(online, 2);
        crate::boot::late_core_class_check(online);
    }
}

/// Record the boot CPU's own core type; does it report one (a hybrid part)?
#[cfg(feature = "energy")]
pub(crate) fn boot_cpu_reports_a_core_type() -> bool {
    azos_arch::ext::hybrid::record_this_cpu(0) != CoreKind::Uniform || canary!("x86-hybrid-synth")
}

/// The class CPU `cpu` recorded when it came up; `None` if it recorded none.
pub(crate) fn recorded_class(cpu: usize) -> Option<CoreClass> {
    // QEMU has one CPU type per machine: the first half are the small cores.
    if canary!("x86-hybrid-synth") {
        let small = cpu < azos_percpu::nr_cpu_ids() / 2;
        return recorded(cpu).map(|_| if small { CoreClass::Efficiency } else { CoreClass::Performance });
    }
    recorded(cpu).map(|k| match k {
        CoreKind::Uniform => CoreClass::Uniform,
        CoreKind::Performance => CoreClass::Performance,
        CoreKind::Efficiency => CoreClass::Efficiency,
        CoreKind::Unrecognised => CoreClass::Unknown,
    })
}

/// The TSC rate in kHz: the one clock x86 can read.
#[cfg(feature = "energy")]
pub(crate) fn tsc_khz() -> u32 {
    (azos_arch::timer::tsc_hz() / 1000).min(u32::MAX as u64) as u32
}
