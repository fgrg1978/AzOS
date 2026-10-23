// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SMP building blocks: tie `cpu` + `gic` + `firmware` + `timer` together
//! into the two call sequences a kernel needs — bring a secondary core up
//! from the primary, and have that secondary core finish its own per-PE
//! init. Wired into `kernel/` since the aarch64 parity program's Phase 4:
//! `secondary_init` (below) is called from the kernel's aarch64
//! `ArchEntry::secondary_irq_init` (`kernel/src/entry/aarch64/arch_entry.rs`), and `kernel/src/entry/aarch64/boot_hooks.rs`'s `arch_wake_
//! secondaries` (`entry::aarch64::boot_hooks`) drives the primary side
//! through `azos_sched::smp::wake_harts` → `ARCH.hart_start` (PSCI
//! `CPU_ON`) — four call sites into this module as of this doc's own
//! last check (`grep -rn "azos_arch::smp::" kernel/src crates`).

#[cfg(target_arch = "aarch64")]
use crate::irq::gic;
#[cfg(target_arch = "aarch64")]
use crate::{cpu, firmware, timer};

#[cfg(target_arch = "aarch64")]
pub use firmware::CpuOnOutcome;

/// Primary-side: bring up the PE at MPIDR affinity `target_affinity`
/// (pack with [`crate::cpu::affinity_key`] /
/// [`crate::cpu::mpidr_affinity_key`]) at `entry_pa`, handing it
/// `context_id` in x0. PSCI leaves the payload's meaning entirely to the
/// caller; the conventional choice is the new PE's boot-stack top, but
/// `crates/core/sched::smp::wake_hart` (the kernel's actual caller) passes
/// `hart_id` instead — its asm entry point computes the stack itself from a
/// `hart_id`-indexed table, the same shape `_secondary_start`'s
/// `secondary_stacks[hart_id]` already uses on RISC-V, rather than trusting
/// an address handed to it with no range check available on that side.
/// Thin wrapper over [`firmware::cpu_on_checked`] — kept here so SMP bring-up
/// code has one module to import for the whole sequence
/// (`start_core` on the primary → ... → `secondary_init` on the new PE).
#[cfg(target_arch = "aarch64")]
pub fn start_core(target_mpidr_packed: u64, entry_pa: u64, context_id: u64) -> CpuOnOutcome {
    firmware::cpu_on_checked(target_mpidr_packed, entry_pa, context_id)
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
/// straight to `gic::enable_ppi_at` without re-deriving it (0 under a GICv2,
/// which has no such frame).
///
/// # Panics
/// In debug builds, if no frame's `TYPER` affinity matches this PE's own
/// MPIDR — that means the redistributor layout this walk assumes
/// (`GICR_BASE`, contiguous frames) disagrees with what's actually wired
/// up, and continuing silently would leave this core's SGI/PPI lines
/// masked with nothing to say why.
#[cfg(target_arch = "aarch64")]
pub fn secondary_init(max_frames: usize) -> usize {
    // A GICv2 (or the BCM2836 pair) has no redistributor to find: the CPU
    // interface and the banked SGI/PPI registers are this PE's own. 0 is then no frame, and
    // `gic::enable_ppi_at` does not read it.
    if crate::irq::gicv2::active() || crate::irq::bcm2836::active() {
        gic::init_cpu_interface();
        timer::init_percpu();
        return 0;
    }
    let me = cpu::read_mpidr();
    let rd_base = gic::find_redistributor(me.affinity_key(), max_frames)
        .expect("no GICR frame matches this PE's own MPIDR affinity");
    gic::init_redistributor_at(rd_base);
    gic::init_cpu_interface();
    timer::init_percpu();
    rd_base
}

// ── Spin table: a CPU the firmware holds without PSCI ──────────────────────
//
// A device tree whose `cpu@N` nodes say `enable-method = "spin-table"` (a
// Raspberry Pi 3) has firmware that parks every secondary in a loop polling
// that CPU's `cpu-release-addr`; a non-zero word there is where the CPU jumps,
// at the exception level and with the MMU off as the firmware left it, with
// no argument. The boot CPU releases each of them, early (while the bootstrap
// identity map still reaches the release word, which on a Pi sits in RAM
// page 0, the page the null guard later unmaps from the linear map), into
// the kernel's own pen (`_aarch64_spin_pen`, boot.S). The pen polls
// [`AZOS_SPIN_GO`] with its MMU off; [`spin_table_start`] later writes the
// CPU's slot with its affinity, and the CPU leaves for
// `_aarch64_secondary_entry` with its logical id in x0, the same entry and
// contract PSCI `CPU_ON` gives.

/// The slot of a logical CPU the pen may start: its MPIDR affinity key
/// ([`crate::cpu::affinity_key`]) with [`SPIN_GO_VALID`] set, 0 while it must
/// wait. Read by `_aarch64_spin_pen` with the MMU off, so every write is
/// cleaned to the point of coherency.
#[unsafe(no_mangle)]
pub static AZOS_SPIN_GO: [core::sync::atomic::AtomicU64; azos_percpu::NR_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; azos_percpu::NR_CPUS];

/// The bit of an [`AZOS_SPIN_GO`] slot that lets its CPU go.
pub const SPIN_GO_VALID: u64 = 1 << 63;

/// The logical CPUs released into the pen ([`spin_table_release`]).
static SPIN_PARKED: [core::sync::atomic::AtomicBool; azos_percpu::NR_CPUS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; azos_percpu::NR_CPUS];

/// The [`AZOS_SPIN_GO`] word that starts the CPU with affinity key `key`.
pub const fn spin_go_word(key: u32) -> u64 {
    SPIN_GO_VALID | key as u64
}

/// Release logical CPU `hart` from the firmware's spin table into the pen at
/// `pen_pa`: write the pen's physical address to the CPU's `release_pa`, clean
/// it to the point of coherency and `sev`. Boot CPU, once per CPU, while the
/// bootstrap identity map covers `release_pa`.
///
/// # Safety
/// `release_pa` must be the CPU's `cpu-release-addr` from the device tree and
/// mapped (identity) writable; `pen_pa` the pen's physical address.
#[cfg(target_arch = "aarch64")]
pub unsafe fn spin_table_release(hart: usize, release_pa: u64, pen_pa: u64) {
    let Some(parked) = SPIN_PARKED.get(hart) else { return };
    unsafe {
        core::ptr::write_volatile(release_pa as *mut u64, pen_pa);
        crate::cache::dcache_clean_and_invalidate(release_pa as usize, 8);
        core::arch::asm!("dsb sy", "sev", options(nostack, preserves_flags));
    }
    parked.store(true, core::sync::atomic::Ordering::Release);
}

/// Was logical CPU `hart` released into the pen?
pub fn spin_table_parked(hart: usize) -> bool {
    SPIN_PARKED.get(hart).is_some_and(|p| p.load(core::sync::atomic::Ordering::Acquire))
}

/// Let logical CPU `hart` (affinity key `key`) out of the pen: it enters
/// `_aarch64_secondary_entry` with `hart` in x0. Its boot stack
/// (`AZOS_SECONDARY_SP`) must be published first, as for PSCI `CPU_ON`.
#[cfg(target_arch = "aarch64")]
pub fn spin_table_start(hart: usize, key: u32) -> bool {
    let Some(slot) = AZOS_SPIN_GO.get(hart) else { return false };
    slot.store(spin_go_word(key), core::sync::atomic::Ordering::Release);
    unsafe {
        crate::cache::dcache_clean(slot as *const _ as usize, 8);
        core::arch::asm!("dsb sy", "sev", options(nostack, preserves_flags));
    }
    true
}
