// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The core types the x86_64 CPUs report (CPUID leaves 0x1A and 0x80000026),
//! as the scheduler's energy model reads them (`boot::energy`). The
//! reading is `azos_arch::ext::hybrid`; shared boot code reaches it only
//! through these three calls, so it names no ISA-specific arch module.

use azos_arch::ext::hybrid::{record_this_cpu, recorded, CoreKind, MAX_RECORDED};
use azos_energy::model::{CoreClass, MAX_MODEL_CPUS};

const _: () = assert!(MAX_RECORDED == MAX_MODEL_CPUS);

/// Record the boot CPU's own core type; does it report one (a hybrid part)?
pub(crate) fn boot_cpu_reports_a_core_type() -> bool {
    record_this_cpu(0) != CoreKind::Uniform
}

/// The class CPU `cpu` recorded when it came up; `None` if it recorded none.
pub(crate) fn recorded_class(cpu: usize) -> Option<CoreClass> {
    recorded(cpu).map(|k| match k {
        CoreKind::Uniform => CoreClass::Uniform,
        CoreKind::Performance => CoreClass::Performance,
        CoreKind::Efficiency => CoreClass::Efficiency,
        CoreKind::Unrecognised => CoreClass::Unknown,
    })
}

/// The TSC rate in kHz: the one clock x86 can read.
pub(crate) fn tsc_khz() -> u32 {
    (azos_arch::timer::tsc_hz() / 1000).min(u32::MAX as u64) as u32
}
