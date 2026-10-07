// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Possible CPUs and per-CPU areas at boot: Linux's `setup_nr_cpu_ids` and
//! `setup_per_cpu_areas`, over `crates/core/percpu`.

use crate::*;

/// Linux's `setup_nr_cpu_ids`: turn the firmware's CPU description into
/// `nr_cpu_ids` and the possible mask, and answer how many CPUs to bring up.
///
/// `fw` is filled by the boot hooks from the platform's tables (the DTB's
/// `/cpus` today, on both ISAs); this function reads no table itself. The
/// answer is `fw.count` cut to the Kconfig ceiling `NR_CPUS`; a cut is a
/// `kwarn`, never a silent `min` (both ISAs used to clamp without a word,
/// riscv64 to a private 4). Possible CPUs are the prefix `0..n`: a CPU id is a
/// hart id on riscv64 and the DTB order on aarch64, and every board this tree
/// targets numbers its harts from 0; the boot CPU is always in it (the caller
/// has checked it is below `NR_CPUS`).
///
/// `nr-cpus-clamp-canary` skips the cut: the count the boot goes on to start
/// and balance over then exceeds the ceiling (the masks still cannot), and
/// the `booting N` line the gate pins says so.
pub(crate) fn discover_cpus(fw: azos_percpu::FirmwareCpus) -> usize {
    #[cfg(not(feature = "nr-cpus-clamp-canary"))]
    let (n, clamped) = azos_percpu::clamp_discovered(fw.count);
    #[cfg(feature = "nr-cpus-clamp-canary")]
    let (n, clamped) = (fw.count.max(1), false);
    if clamped {
        azos_drv_sys::kwarn!(
            "[SMP] {} names {} CPUs, NR_CPUS is {}: the rest are never started (raise NR_CPUS in make config)",
            fw.source, fw.count, azos_percpu::NR_CPUS);
    } else if fw.count == 0 {
        azos_drv_sys::kwarn!("[SMP] no CPU count from the firmware ({}): booting on the boot CPU alone", fw.source);
    }
    // A prefix, always: `0..max(n, boot_cpu + 1)`, so "possible" and "below
    // nr_cpu_ids" are the same test (the scheduler's `ncpu()` relies on it).
    // (A VF2 whose DTB counted only the four U74s while hart 4 won the boot
    // lock would otherwise have no area on the CPU executing this line.)
    let possible = azos_percpu::CpuMask::first_n(n.max(fw.boot_cpu + 1));
    azos_percpu::set_possible(&possible);
    kprintln!("[SMP] CPUs from {}: {}, booting {} (possible {}, nr_cpu_ids {}, NR_CPUS {})",
        fw.source, fw.count, n, azos_percpu::possible().weight(), azos_percpu::nr_cpu_ids(),
        azos_percpu::NR_CPUS);
    n
}

/// Most per-CPU variables the list below may name (a capacity, not a
/// tunable: the build fails loudly if the list outgrows it).
const MAX_PERCPU_VARS: usize = 16;

/// Filler for the unused tail of the variable list.
// SAFETY: `()` is zero-sized; any bytes are a valid `()`.
static NO_VAR: azos_percpu::PerCpu<()> = unsafe { azos_percpu::PerCpu::zeroed() };

/// Bytes of one per-CPU area, as `setup_per_cpu_areas` laid it out (0 before).
static AREA_BYTES: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Visit every per-CPU variable the kernel keeps in the areas, in layout order.
fn with_percpu_vars<R>(f: impl FnOnce(&[&'static dyn azos_percpu::PerCpuVar]) -> R) -> R {
    let mut vars: [&'static dyn azos_percpu::PerCpuVar; MAX_PERCPU_VARS] = [&NO_VAR; MAX_PERCPU_VARS];
    let mut n = 0usize;
    let mut add = |v: &'static dyn azos_percpu::PerCpuVar| {
        assert!(n < MAX_PERCPU_VARS, "more per-CPU variables than MAX_PERCPU_VARS");
        vars[n] = v;
        n += 1;
    };
    azos_sched::for_each_percpu_var(&mut add);
    azos_trace::for_each_percpu_var(&mut add);
    f(&vars[..n])
}

/// Page size of the frame allocator, from the Kconfig `PAGE_SHIFT`.
const PAGE_BYTES: usize = 1 << azos_limits::PAGE_SHIFT;

/// Bytes at the bottom of a secondary CPU's area holding its two stacks:
/// `[boot stack SECONDARY_STACK_SIZE][interrupt stack IRQ_STACK_SIZE]`,
/// rounded up to `AREA_ALIGN` so the variables above start aligned.
///
/// The order is deliberate. The interrupt stack carries its magic word at
/// its bottom, so an interrupt-stack overflow is caught there and runs, past
/// it, into the top of the boot stack, which is dead once the CPU has
/// switched to its first task. The boot stack's own overflow runs below the
/// area, as it ran into the next `.bss` slot when these were static.
const STACKS_BYTES: usize =
    (SECONDARY_STACK_SIZE + IRQ_STACK_SIZE).div_ceil(azos_percpu::AREA_ALIGN) * azos_percpu::AREA_ALIGN;

/// Linux's `setup_per_cpu_areas`: one area per possible CPU, from the frame
/// allocator, each holding an instance of every per-CPU variable, attached
/// before anything can touch one; a secondary CPU's area also holds its
/// boot and interrupt stacks (`STACKS_BYTES`), published in
/// `AZOS_SECONDARY_SP` / `AZOS_IRQ_STACK_BASE` for the asm. The boot CPU
/// keeps the linker's boot stack and the static `boot_irq_stack`, both in
/// use before this runs. Runs once on the boot CPU, after the heap and
/// before the scheduler is initialised, the first task is created or a
/// secondary CPU is started; a CPU that cannot get its area halts the boot
/// (it could not run a single task).
///
/// Nothing in `.bss` scales with the possible CPUs any more; what still
/// scales with the Kconfig ceiling `NR_CPUS` is a word or two per CPU
/// (ARCHITECTURE.md, "SMP and per-CPU state", lists each table and why it
/// stays static).
pub(crate) fn setup_per_cpu_areas() {
    use azos_arch::{Cpu, ARCH};
    // `ipc-census`: run the ISR's ring audit once here, before any area
    // exists, the deterministic form of a first tick that lands in this
    // window. It must skip the CPUs without an area; a walk that does not
    // takes a kernel load fault at POISON on every `ipc-census` boot (the
    // `mem quota: refusals>0 (N)` row and the other census rows go red).
    #[cfg(feature = "ipc-census")]
    let _ = azos_sched::ring_claim_audit();
    let boot = boot_cpu();
    with_percpu_vars(|vars| {
        let bytes = azos_percpu::area_bytes(vars);
        AREA_BYTES.store(bytes, Ordering::Relaxed);
        let mut total = 0usize;
        for cpu in azos_percpu::possible().iter() {
            let stacks = if cpu == boot { 0 } else { STACKS_BYTES };
            let size = stacks + bytes;
            if size == 0 {
                continue;
            }
            let pa = match azos_mm::pmm::alloc_contiguous(size.div_ceil(PAGE_BYTES)) {
                Ok(pa) => pa.as_usize(),
                Err(e) => {
                    azos_drv_sys::kerr!("[PERCPU] FATAL: no {} KiB for CPU {}'s area ({:?})", size >> 10, cpu, e);
                    ARCH.halt();
                }
            };
            total += size;
            let va = azos_mm::addr::phys_to_virt(pa);
            if stacks != 0 {
                // The interrupt stack first (magic, then its base), then the
                // boot stack's top — as a PHYSICAL address: the secondary
                // reads it before its MMU is on.
                crate::boot::arm_irq_stack(cpu, va + SECONDARY_STACK_SIZE);
                AZOS_SECONDARY_SP[cpu].store(pa + SECONDARY_STACK_SIZE, Ordering::Release);
            }
            // SAFETY: `alloc_contiguous` returned zeroed, page-aligned frames
            // owned by nobody else, reached at `va` through the kernel's
            // linear map; `va + stacks` is `AREA_ALIGN`-aligned; only the boot
            // CPU runs and no variable is in use yet.
            unsafe { azos_percpu::attach_area(vars, cpu, (va + stacks) as *mut u8) };
        }
        kprintln!("[PERCPU] {} area(s): {} B of variables ({}) each, +{} B of stacks per secondary; \
            {} KiB from the frame allocator; NR_CPUS {}",
            azos_percpu::possible().weight(), bytes, vars.len(), STACKS_BYTES, total >> 10,
            azos_percpu::NR_CPUS);
    });
    percpu_self_check();
}

/// The CPU running the boot (its per-CPU base, read through arch-api).
fn boot_cpu() -> usize {
    use azos_arch::{Cpu, ARCH};
    ARCH.percpu_base()
}

/// Bytes of one per-CPU area (0 before `setup_per_cpu_areas`).
#[allow(dead_code)]
pub(crate) fn percpu_area_bytes() -> usize {
    AREA_BYTES.load(Ordering::Relaxed)
}

/// The property the areas exist for, checked once at boot: every possible CPU
/// has its instance, and a CPU past `nr_cpu_ids` has none — its slot holds the
/// faulting `POISON` address and the checked accessor refuses it (counted).
/// `percpu-oor-canary` attaches an area past `nr_cpu_ids` (what a setup that
/// walked `NR_CPUS` instead of the possible mask would do) and this line
/// turns red.
fn percpu_self_check() {
    with_percpu_vars(|vars| {
        let n = azos_percpu::nr_cpu_ids();
        #[cfg(feature = "percpu-oor-canary")]
        if n < azos_percpu::NR_CPUS {
            // Page-aligned: `attach_area` asserts `AREA_ALIGN`, and a bare
            // `[u8; _]` static is byte-aligned, so the canary panicked in that
            // assert instead of reaching the self-check (gate, wave 15
            // integration: the rv canary row timed out, the boot silent after
            // the `[PERCPU] ... area(s)` line).
            #[repr(C, align(4096))]
            struct CanaryArea([u8; 4096 * 64]);
            static mut CANARY_AREA: CanaryArea = CanaryArea([0; 4096 * 64]);
            let b = azos_percpu::area_bytes(vars);
            if b <= 4096 * 64 {
                // SAFETY: a canary build only; the static is used by nothing else.
                unsafe { azos_percpu::attach_area(vars, n, (&raw mut CANARY_AREA) as *mut u8) };
            }
        }
        let missing = (0..n).filter(|&c| vars.iter().any(|v| !v.attached(c))).count()
            + (0..n).filter(|&c| crate::boot::irq_stack_base(c) == 0).count()
            + (0..n).filter(|&c| c != boot_cpu() && AZOS_SECONDARY_SP[c].load(Ordering::Relaxed) == 0).count();
        let before = azos_percpu::oor_count();
        let caught = n >= azos_percpu::NR_CPUS
            || (vars.iter().all(|v| !v.attached(n)) && azos_percpu::checked_area(n).is_none());
        let counted = azos_percpu::oor_count() > before || n >= azos_percpu::NR_CPUS;
        if missing == 0 && caught && counted {
            kprintln!("[PERCPU] self-check: CPUs 0..{} attached, CPU {} past nr_cpu_ids refused (POISON {:#x}): PASS",
                n, n, azos_percpu::POISON);
        } else {
            azos_drv_sys::kerr!("[PERCPU] self-check FAILED: {} CPU(s) below nr_cpu_ids {} without an area, \
                CPU {} past it {}", missing, n, n, if caught { "refused" } else { "HAS AN AREA" });
        }
    });
}

// Kconfig KTEST: the boot self-check above, re-read after boot init. Its
// `percpu-oor-canary` (an area attached past `nr_cpu_ids`) must turn this
// test `not ok`. A separate copy of the three findings, not a helper shared
// with `percpu_self_check`: the boot path stays byte-identical with KTEST off.
#[cfg(feature = "ktest")]
mod ktests {
    use super::*;

    azos_ktest::ktest! {
        fn percpu_areas_and_oor_refusal() {
            let (missing, caught, counted) = with_percpu_vars(|vars| {
                let n = azos_percpu::nr_cpu_ids();
                let missing = (0..n).filter(|&c| vars.iter().any(|v| !v.attached(c))).count()
                    + (0..n).filter(|&c| crate::boot::irq_stack_base(c) == 0).count()
                    + (0..n).filter(|&c| c != boot_cpu() && AZOS_SECONDARY_SP[c].load(Ordering::Relaxed) == 0).count();
                let before = azos_percpu::oor_count();
                let caught = n >= azos_percpu::NR_CPUS
                    || (vars.iter().all(|v| !v.attached(n)) && azos_percpu::checked_area(n).is_none());
                let counted = azos_percpu::oor_count() > before || n >= azos_percpu::NR_CPUS;
                (missing, caught, counted)
            });
            if missing != 0 {
                Err("a CPU below nr_cpu_ids has no per-CPU area, IRQ stack or boot stack")
            } else if !caught {
                Err("CPU nr_cpu_ids has a per-CPU area")
            } else if !counted {
                Err("the out-of-range access was not counted")
            } else {
                Ok(())
            }
        }
    }
}
