// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SMP building blocks: tie `mpidr` + `gic` + `psci` + `timer` together
//! into the two call sequences a kernel needs — bring a secondary core up
//! from the primary, and have that secondary core finish its own per-PE
//! init. Wired into `kernel/` since the aarch64 parity program's Phase 4:
//! `secondary_init` (below) is called from `kernel::entry::aarch64::
//! aarch64_smp_secondary_start`, and `kernel/src/entry/aarch64/boot_hooks.rs`'s `arch_wake_
//! secondaries` (`entry::aarch64::boot_hooks`) drives the primary side
//! through `azos_sched::smp::wake_harts` → `ARCH.hart_start` (PSCI
//! `CPU_ON`) — four call sites into this module as of this doc's own
//! last check (`grep -rn "azos_arch::smp::" kernel/src crates`).

#[cfg(target_arch = "aarch64")]
use crate::{gic, mpidr, psci, timer};

#[cfg(target_arch = "aarch64")]
pub use psci::CpuOnOutcome;

/// Primary-side: bring up the PE at MPIDR affinity `target_affinity`
/// (pack with [`crate::mpidr::affinity_key`] /
/// [`crate::mpidr::mpidr_affinity_key`]) at `entry_pa`, handing it
/// `context_id` in x0. PSCI leaves the payload's meaning entirely to the
/// caller; the conventional choice is the new PE's boot-stack top, but
/// `crates/core/sched::smp::wake_hart` (the kernel's actual caller) passes
/// `hart_id` instead — its asm entry point computes the stack itself from a
/// `hart_id`-indexed table, the same shape `_secondary_start`'s
/// `secondary_stacks[hart_id]` already uses on RISC-V, rather than trusting
/// an address handed to it with no range check available on that side.
/// Thin wrapper over [`psci::cpu_on_checked`] — kept here so SMP bring-up
/// code has one module to import for the whole sequence
/// (`start_core` on the primary → ... → `secondary_init` on the new PE).
#[cfg(target_arch = "aarch64")]
pub fn start_core(target_mpidr_packed: u64, entry_pa: u64, context_id: u64) -> CpuOnOutcome {
    psci::cpu_on_checked(target_mpidr_packed, entry_pa, context_id)
}

/// Secondary-side: this core's own per-PE bring-up. Call once, early —
/// after this PE's MMU + VBAR_EL1 are set up (see the integration order
/// in this crate's owning agent's report), before unmasking IRQs.
///
/// Finds this PE's OWN redistributor frame by walking `GICR_TYPER`
/// affinity (never by assuming frame index == boot/core index — see
/// [`gic::find_redistributor`]'s doc), initialises it, enables the CPU
/// interface, and parks the generic timer in a known state.
///
/// `max_frames` bounds the walk to however many redistributor frames the
/// caller has actually MMIO-mapped — walking past that reads unmapped
/// memory. Returns the frame's `RD_base`, so the caller can feed it
/// straight to `gic::enable_ppi_at` without re-deriving it.
///
/// # Panics
/// In debug builds, if no frame's `TYPER` affinity matches this PE's own
/// MPIDR — that means the redistributor layout this walk assumes
/// (`GICR_BASE`, contiguous frames) disagrees with what's actually wired
/// up, and continuing silently would leave this core's SGI/PPI lines
/// masked with nothing to say why.
#[cfg(target_arch = "aarch64")]
pub fn secondary_init(max_frames: usize) -> usize {
    let me = mpidr::read_mpidr();
    let rd_base = gic::find_redistributor(me.affinity_key(), max_frames)
        .expect("no GICR frame matches this PE's own MPIDR affinity");
    gic::init_redistributor_at(rd_base);
    gic::init_cpu_interface();
    timer::init_percpu();
    rd_base
}
