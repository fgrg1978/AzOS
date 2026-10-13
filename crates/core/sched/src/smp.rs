// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SMP support for the AzOS scheduler.
//!
//! **RISC-V:** starts secondary harts via SBI HSM `hart_start` (same
//! approach as the C kernel's `sbi_hart_start()` in kernel/core/smp.c).
//! OpenSBI parks secondary harts in M-mode by default; they must be
//! explicitly started via HSM, not via a polling flag.
//!
//! **aarch64:** starts secondary PEs via PSCI `CPU_ON`
//! (`arch-aarch64::smp::start_core`), targeting the MPIDR affinity
//! [`set_hart_affinity`] published from the DTB `/cpus` nodes — see
//! [`wake_hart`]'s own doc for the full sequence and this kernel's own
//! `context_id` convention.

use core::sync::atomic::AtomicUsize;

// arch-only: the aarch64 MPIDR affinity table below.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::sync::atomic::{AtomicU32, Ordering as SmpOrdering};

/// Pure liveness accounting for [`wake_harts`], in its own file only so the
/// host test runner can compile it (this module cannot leave the target: it
/// reads `tp` with inline assembly and links against `_secondary_start`).
#[path = "hart_set.rs"]
pub mod hart_set;

/// Number of CPUs currently considered online for task distribution.
///
/// Published in two steps by the boot CPU:
/// 1. Before task creation, set to the *expected* CPU count (from the DTB)
///    so that the boot-time `task_create` calls — which run before any
///    secondary hart exists and must pre-populate per-CPU ready queues that
///    can't be touched cross-CPU afterwards — spread across all intended
///    CPUs.
/// 2. After [`wake_harts`] reports how many secondary harts actually started,
///    corrected down to the real count. This is what matters for any task
///    created later (e.g. `fork()`): without the correction, a hart that
///    failed `hart_start` keeps an empty ready queue forever, which
///    `find_best_cpu` reads as the least contended CPU and routes tasks to
///    it forever — see [`hart_set`] for why the published value must be a
///    live *prefix* bound, not a plain headcount.
/// Secondary CPUs do NOT write this — the boot CPU owns it exclusively.
pub static NUM_ONLINE_CPUS: AtomicUsize = AtomicUsize::new(1);

// ---- External symbols ----

#[cfg(target_arch = "riscv64")]
unsafe extern "C" {
    /// Secondary CPU entry point defined in kernel/src/asm/boot.S.
    /// OpenSBI will jump to this address (in S-mode) when `sbi::hart_start` is called.
    fn _secondary_start();
}

// ---- Hart wakeup via SBI HSM ----

/// Start secondary hart `hart_id` via SBI HSM `hart_start`.
///
/// Returns the raw SBI error code: `0` (`SBI_SUCCESS`) on success, negative
/// on failure (`SBI_ERR_INVALID_PARAM`, `SBI_ERR_ALREADY_AVAILABLE`, hart not
/// present, ...). Callers MUST check this — a hart that fails to start never
/// runs `_secondary_start`, so its per-CPU ready queue stays empty forever.
#[cfg(target_arch = "riscv64")]
pub unsafe fn wake_hart(hart_id: usize) -> isize {
    // Before the hart can run: the shootdown scan must already cover it.
    azos_arch::tlb::note_hart_online(hart_id);
    let entry = _secondary_start as *const () as usize;
    azos_arch::sbi::hart_start(hart_id, entry, hart_id)
}

/// aarch64: hart id → MPIDR affinity table, published by the boot CPU from
/// the DTB `/cpus` nodes (`azos_dtb::dtb_cpu_regs`) BEFORE [`wake_harts`]
/// runs — see `kernel/src/main.rs`'s SMP bring-up tail.
///
/// `hart_id` here is NOT `Aff0` — it is this kernel's own small integer, the
/// index a hart's `cpu@N` node appears at in the DTB's document order (entry
/// 0 is always the boot CPU: `boot.S`'s primary-selection check requires
/// `Aff0=Aff1=Aff2=0`, and every DTB this tree has seen — real or
/// QEMU-generated — lists that PE first). PSCI `CPU_ON`, GICR discovery and
/// the SGI target list all need the REAL affinity, which on a
/// non-flat topology need not equal `Aff0` — "do not assume aff0 == hart" is
/// this table's whole reason to exist, not a caveat on it.
///
/// Packed via `azos_arch::mpidr::affinity_key` (`Aff3<<24 | Aff2<<16 |
/// Aff1<<8 | Aff0`) — the same shape `gic::find_redistributor` and
/// `gic::typer_affinity_key` already use, so a value read out of this table
/// needs no repacking to match a redistributor frame. `u32::MAX` marks "not
/// yet published" (a real affinity's top byte, Aff3, is vanishingly unlikely
/// to be 0xFF on any board this tree targets, and even if it were, `wake_hart`
/// below still only trusts an entry `NUM_ONLINE_CPUS`/the DTB actually named —
/// this sentinel only guards against reading a table slot nobody wrote).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub const AARCH64_HART_TABLE_LEN: usize = azos_percpu::NR_CPUS;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
const HART_AFFINITY_UNSET: u32 = u32::MAX;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
static HART_AFFINITY: [AtomicU32; AARCH64_HART_TABLE_LEN] =
    [const { AtomicU32::new(HART_AFFINITY_UNSET) }; AARCH64_HART_TABLE_LEN];

/// Publish `hart_id`'s real MPIDR affinity (packed, see [`HART_AFFINITY`]'s
/// doc). Called only by the boot CPU, only before [`wake_harts`] — the same
/// "boot CPU owns this exclusively, before any secondary can race it"
/// contract [`NUM_ONLINE_CPUS`] documents. Silently drops an out-of-range
/// `hart_id` (mirrors `boot.S`'s own `MAX_HARTS` range check on the
/// receiving end — a DTB naming more CPUs than this table holds degrades to
/// "the extra ones never start", not a panic).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn set_hart_affinity(hart_id: usize, affinity_key: u32) {
    if let Some(slot) = HART_AFFINITY.get(hart_id) {
        slot.store(affinity_key, SmpOrdering::Relaxed);
    }
}

/// Read back `hart_id`'s published affinity, or `None` if it was never set
/// (out of range, or the DTB had fewer `cpu@` nodes than `hart_id`).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn hart_affinity(hart_id: usize) -> Option<u32> {
    let v = HART_AFFINITY.get(hart_id)?.load(SmpOrdering::Relaxed);
    if v == HART_AFFINITY_UNSET { None } else { Some(v) }
}

// Secondary CPU entry point defined in
// `kernel/src/entry/aarch64/asm/boot.S`. PSCI `CPU_ON` starts the target PE
// here with `x0` = the `context_id` `wake_hart` (below) passes — THIS
// kernel's own convention is `hart_id` (not "the new PE's boot-stack top",
// the generic convention `arch-aarch64::smp::start_core`'s doc describes):
// the asm entry computes its own stack from a `hart_id`-indexed table,
// exactly mirroring `_secondary_start`'s `secondary_stacks[hart_id]` above,
// rather than trusting a stack address handed to it with no range check
// available on this side.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
unsafe extern "C" {
    fn _aarch64_secondary_entry();
}

/// Start secondary hart `hart_id` via PSCI `CPU_ON`, targeting the MPIDR
/// affinity [`set_hart_affinity`] published for it.
///
/// Returns `0` on `Success`/`AlreadyOn` (an already-on PE is the caller's
/// desired end state, same as the RISC-V arm treating `SBI_ERR_ALREADY_
/// AVAILABLE` as fine would if it checked — it doesn't, PSCI's decoded
/// outcome here does), `-1` otherwise — including "no affinity published for
/// this hart_id", which happens when the DTB reported fewer CPUs than
/// `num_cpus` claimed, or `hart_id >= AARCH64_HART_TABLE_LEN`.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn wake_hart(hart_id: usize) -> isize {
    let Some(affinity) = hart_affinity(hart_id) else {
        azos_drv_sys::kwarn!(
            "[SMP] hart {} has no published MPIDR affinity (DTB had fewer \
             cpu@ nodes than expected) — not starting it", hart_id);
        return -1;
    };

    // Unpack the gic/mpidr `affinity_key` shape (Aff3 at bits [31:24]) into
    // PSCI's `target_cpu` shape (Aff3 at bits [39:32] — see
    // `mpidr::Mpidr::pack_for_psci`). Same four bytes, different bit
    // positions; conflating them sends `CPU_ON` a target that silently
    // decodes to a different PE (or none) whenever Aff3 != 0.
    let aff0 = (affinity & 0xFF) as u8;
    let aff1 = ((affinity >> 8) & 0xFF) as u8;
    let aff2 = ((affinity >> 16) & 0xFF) as u8;
    let aff3 = ((affinity >> 24) & 0xFF) as u8;
    let target_cpu = azos_arch::mpidr::Mpidr::pack_for_psci(aff0, aff1, aff2, aff3);

    // PSCI `CPU_ON` takes a PHYSICAL entry point — `_aarch64_secondary_entry`
    // is the kernel's own symbol address, identical to its PA today
    // (`virt_to_phys` is a no-op until the aarch64 TTBR1 migration links the
    // kernel high — see `azos_mm::addr`'s module doc), but the target PE
    // starts with its MMU off and BOOTS from the value handed here, so this
    // must always be the PA, never whatever VA the kernel happens to see its
    // own code at.
    let entry = azos_mm::addr::virt_to_phys(_aarch64_secondary_entry as *const () as usize);
    match azos_arch::smp::start_core(target_cpu, entry as u64, hart_id as u64) {
        azos_arch::smp::CpuOnOutcome::Success
        | azos_arch::smp::CpuOnOutcome::AlreadyOn => 0,
        outcome => {
            azos_drv_sys::kwarn!(
                "[SMP] hart {} PSCI CPU_ON failed: {:?}", hart_id, outcome);
            -1
        }
    }
}

#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
unsafe extern "C" {
    /// The 64-bit AP entry (kernel/src/entry/x86_64/asm/ap_entry.S): %rdi =
    /// the CPU number, which it also uses for its stack and per-CPU base.
    fn _secondary_start();
}

/// x86_64 (and any further ISA): INIT-SIPI-SIPI to the MADT APIC ID of
/// `hart_id` through `Boot::hart_start`, which returns once the AP has
/// reached 64-bit mode. 0 on success, -1 otherwise (logged).
#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
pub unsafe fn wake_hart(hart_id: usize) -> isize {
    let entry = _secondary_start as *const () as usize;
    match azos_arch::Boot::hart_start(&azos_arch::ARCH, hart_id, entry, hart_id) {
        Ok(()) => 0,
        Err(e) => {
            azos_drv_sys::kwarn!("[SMP] CPU {} INIT-SIPI-SIPI failed: {:?}", hart_id, e);
            -1
        }
    }
}

/// Start every secondary hart in `0..num_cpus` (boot hart excluded — it is
/// already running).
///
/// Returns the number of CPUs the caller should publish as
/// [`NUM_ONLINE_CPUS`]. `find_best_cpu` in `scheduler.rs` reads that value as
/// a live *prefix* bound (`for i in 0..num_online`, indexing `PER_CPU[i]`
/// directly), and `rebalance_from_offline_cpus(online, total)` reads
/// `online..total` as the dead harts — not a plain headcount of successes.
/// Every hart is still attempted regardless of earlier failures; only the
/// published prefix shrinks. See [`hart_set`] for the full contract, for why
/// the old `online = 1` seed silently assumed the boot hart was hart 0, and
/// for what that cost when it was hart 2.
///
/// The boot hart identifies itself through [`current_cpu_id`], which is
/// correct here without help: `wake_harts` runs on the boot hart inside
/// `kernel_main`, and `boot.S` sets `tp = a0 = hart_id` before calling it.
/// (`boot.S` also publishes a `boot_hart_id` word, but that exists for the
/// *trap* path, which has no `tp` it can trust after a trap from U-mode.
/// Nothing here needs it — the defect was the accounting, not the
/// identification.)
///
/// ASSUMPTION still standing (pre-existing, not fixed here): hart IDs are
/// contiguous `0..num_cpus`. True for QEMU virt; a real board's DTB may
/// enumerate non-contiguous hart IDs, which would need walking the DTB cpu
/// nodes instead of this range — and would also break the prefix contract
/// above, since `PER_CPU` is indexed by hart id. "The boot hart is 0" is no
/// longer assumed anywhere in this file.
pub unsafe fn wake_harts(num_cpus: usize) -> usize {
    let boot = current_cpu_id();
    let mut alive = hart_set::mark_alive(0, boot); // boot hart is already running
    // The online mask (`azos_percpu::online`) is the SET of running CPUs,
    // kept apart from the possible mask so a later hotplug is a bit flip;
    // `NUM_ONLINE_CPUS` below stays the prefix the scheduler walks.
    azos_percpu::set_cpu_online(boot, true);
    // The boot hart publishes roots too; other harts' shootdowns must scan it.
    // riscv64 and x86_64 have no broadcast invalidate, so the boot CPU joins
    // the shootdown's IPI scan (aarch64 needs nothing: TLBI ...IS).
    // arch-only: aarch64's broadcast TLBI has no scan to join.
    #[cfg(any(target_arch = "riscv64", all(target_arch = "x86_64", target_os = "none")))]
    azos_arch::tlb::note_hart_online(boot);

    for hart_id in 0..num_cpus {
        if hart_id == boot {
            continue;
        }
        let ret = wake_hart(hart_id);
        if ret == 0 {
            alive = hart_set::mark_alive(alive, hart_id);
            azos_percpu::set_cpu_online(hart_id, true);
        } else {
            azos_drv_sys::kwarn!(
                "[SMP] hart {} failed to start (sbi hart_start error {})",
                hart_id, ret
            );
        }
    }

    let online = hart_set::online_prefix(alive, num_cpus);

    // A hart that came up but sits past the first dead one gets no work at
    // all, because the published value is a prefix. That is the intended
    // conservative outcome, but silently idling a working CPU is exactly the
    // kind of thing that reads as "SMP is just slow" months later.
    let stranded = hart_set::stranded(alive, num_cpus);
    if stranded != 0 {
        azos_drv_sys::kwarn!(
            "[SMP] harts alive past the first dead one (mask {:#x}) will stay idle: \
             NUM_ONLINE_CPUS is a prefix bound, not a set",
            stranded
        );
    }

    // Two very different situations, both worth a line of UART because no
    // other message describes either one:
    //
    //  a) some hart below the boot hart failed to start. The boot hart keeps
    //     running the kernel, but it is outside `0..online`, so
    //     `find_best_cpu` will never place a task on it and
    //     `rebalance_from_offline_cpus` counts its queue as belonging to a
    //     dead hart.
    //
    //  b) `boot >= num_cpus` outright. Every per-CPU table is sized by the
    //     Kconfig ceiling `NR_CPUS`, and `boot::discover_cpus` adds the boot
    //     hart to the possible mask, so it has its slots and its area; but
    //     `num_cpus` is the DTB's count, so on a board whose boot hart id is
    //     at or past it (the VF2/JH7110 case if its DTB counted only the
    //     U74s 1..4) the boot hart runs the kernel outside the online prefix
    //     and receives no balanced work. This print is the warning for it,
    //     reached before `sched::start()`.
    if boot >= online {
        azos_drv_sys::kwarn!(
            "[SMP] WARNING: boot hart {} is outside the online prefix 0..{} \
             — it runs the kernel but will receive no balanced work",
            boot, online
        );
    }

    online
}

// ---- Current CPU identity ----

/// Returns the current CPU's hart ID from the per-hart register the boot asm
/// parks it in.
///
/// **riscv64:** `tp`, set to `hart_id` in `boot.S` for every hart, primary and
/// secondary. Rust does not use `tp` in `no_std` bare-metal builds. Note `tp`
/// is an ordinary GPR that EL0 (U-mode) can write, which is the whole reason
/// `trap_entry.S` re-establishes it before any Rust runs (K-C16).
///
/// **aarch64:** `TPIDR_EL1`, which is only writable at EL1 — so the K-C16
/// apparatus has no aarch64 counterpart, and the boot asm's `msr TPIDR_EL1` is
/// the only writer. Added 2026-09-19: this function was `mv {}, tp`
/// unconditionally, so the whole scheduler was riscv-only at its most basic
/// call.
#[inline(always)]
pub fn current_cpu_id() -> usize {
    let id: usize;
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("mv {}, tp", out(reg) id, options(nostack, nomem));
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("mrs {}, TPIDR_EL1", out(reg) id, options(nostack, nomem));
    }
    // x86_64: the kernel GS base is this CPU's `PerCpu`, whose first word is
    // the id (`azos_arch::cpu`); ring 3 reaches GS only through `swapgs`,
    // which the trap entry undoes before any Rust runs.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        id = azos_arch::cpu::percpu_id();
    }
    // A host build (tests) has no per-hart register and no SMP: everything runs
    // on "CPU 0", which is what the host shims already assume.
    #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", all(target_arch = "x86_64", target_os = "none"))))]
    {
        id = 0;
    }
    #[cfg(feature = "cpuid-probe")]
    crate::cpuid_probe::observe(id);
    id
}
