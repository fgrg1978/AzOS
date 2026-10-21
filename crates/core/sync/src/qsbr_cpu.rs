// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Which CPU QSBR is running on: the logical CPU id.
//!
//! QSBR's per-CPU words (`CPUS[cpu]`), the mask checks (RCU_NOCBS_CPUS, the
//! tickless set) and the grace-period snapshot are all indexed by the logical
//! CPU id, the id `azos_percpu` and the scheduler's `PER_CPU` use. On every ISA
//! that is what `Cpu::hart_id` answers (`tp`, `TPIDR_EL1`, `%gs:0`): dense,
//! the boot CPU is 0, whatever the hardware numbers its CPUs by (a non-zero
//! boot hart, sparse hart ids: `azos_percpu::hw_id` maps the logical id to the
//! hardware one at the SBI/PLIC/IPI boundary, and nothing here sees it). So
//! there is no indirection to install: QSBR reads the id the way every other
//! per-CPU table does.
//!
//! A child file of `qsbr.rs` so the host suite pulls it by path
//! (`tests/host/sync-tests/src/qsbr_cpuid.rs`).

use azos_arch::{Cpu as _, ARCH};

/// This CPU's logical id: what indexes every per-CPU QSBR word and every
/// CPU mask ([`cpu_in_mask`](crate::qsbr_core::cpu_in_mask)).
#[inline(always)]
pub fn this_cpu() -> usize {
    ARCH.hart_id()
}
