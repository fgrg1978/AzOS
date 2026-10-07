// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The rest of the arch contract: what both ISAs share beyond the five
//! original traits, as REQUIRED methods (no defaults), so a new ISA learns
//! what it must provide from the compiler, not from a grep.
//!
//! Two traits, split by who implements them:
//!
//! * [`ArchPlatform`] — ISA primitives the shared crates need (cache and TLB
//!   maintenance for code writes, user page-table roots, user-memory access
//!   windows, fast page zeroing). Implemented by each ISA crate, on the same
//!   zero-sized singleton as `Cpu`/`Mmu`/..., so every call through
//!   `azos_arch::ARCH` is `#[inline]` and static: no `dyn`, no table.
//! * [`ArchEntry`] — the kernel's boot sequence hooks. Implemented by the
//!   KERNEL (`kernel/src/entry/<isa>/`), not by the ISA crates, because the
//!   hooks drive kernel subsystems (allocator, device tree, scheduler). The
//!   kernel implements it on a kernel-local zero-sized type; `kernel_main`
//!   calls it through one `ARCH_ENTRY` constant chosen in exactly one `cfg`
//!   block with a `compile_error!` for any other ISA.

/// ISA primitives shared crates call instead of reaching into an ISA module.
pub trait ArchPlatform: Send + Sync {
    /// `true` when instruction fetch observes a data write only after the
    /// written D-cache lines are cleaned to the point of unification (aarch64);
    /// `false` when an instruction-fetch fence alone suffices (riscv64).
    /// A method returning a constant, not an associated const, for the
    /// reason `Mmu::levels` gives: callers reach the ISA through the `ARCH`
    /// value, never by naming its type. Both impls are `#[inline]`, so the
    /// clean loop a caller guards with it folds away.
    fn icache_needs_dcache_clean(&self) -> bool;

    /// Clean `[va, va + len)` of the data cache to the point of unification.
    /// A no-op where instruction fetch is coherent with data writes.
    ///
    /// # Safety
    /// `[va, va + len)` must be mapped in the current translation regime.
    unsafe fn dcache_clean(&self, va: usize, len: usize);

    /// Make every CPU's instruction fetch observe all data writes this CPU
    /// made before the call (local fence plus the remote broadcast).
    fn icache_sync_all(&self);

    /// Invalidate the translation of the page holding `va` on EVERY CPU.
    fn flush_tlb_page_all(&self, va: usize);

    /// Zero `[va, va + len)` with the fastest primitive the CPU offers
    /// (cache-block zero where present, plain stores otherwise).
    ///
    /// # Safety
    /// `[va, va + len)` must be mapped writable and owned by the caller.
    unsafe fn zero_memory(&self, va: usize, len: usize);

    /// The ISA's encoding of a user address-space root: what the user root
    /// register takes for table `root_phys` tagged `asid` (riscv64: a `satp`
    /// word; aarch64: the table PA, ASID applied at install).
    fn user_root_word(&self, root_phys: usize, asid: u16) -> usize;

    /// Install `word` (from [`Self::user_root_word`]) as this CPU's user
    /// root and flush this CPU's stale translations. A zero word leaves the
    /// current root in place on ISAs where zero is not a valid root.
    fn install_user_root_local(&self, word: usize);

    /// RAII window during which the kernel may touch user memory (riscv64
    /// `sstatus.SUM`, aarch64 `PSTATE.PAN` clear, x86 `stac`/`clac`).
    type UserAccess;

    /// Open a user-memory access window; it closes when the value drops.
    fn user_access(&self) -> Self::UserAccess;
}

/// The kernel boot sequence, per ISA (see the module doc for why the kernel,
/// not the ISA crate, implements it).
pub trait ArchEntry {
    /// What the early hook hands back to `kernel_main` (heap bounds, CPU
    /// count, ...). A kernel type, so arch-api cannot name it.
    type Early;

    /// First Rust on the boot CPU: console, firmware table (`fw_table`, the
    /// DTB pointer on riscv64/aarch64), memory map, allocator, MMU. CPU
    /// discovery happens here: the hook hands the firmware's CPU count
    /// (DTB `cpu@` nodes; ACPI MADT on a port that has no DTB) to the
    /// kernel's per-CPU set-up (`boot::discover_cpus`).
    fn early_boot(&self, hart_id: usize, fw_table: usize) -> Self::Early;

    /// Map device windows the early map did not cover, once the heap exists.
    fn map_late_mmio(&self);

    /// Start every secondary CPU up to `num_cpus` (SBI HSM, PSCI, INIT-SIPI).
    fn wake_secondaries(&self, num_cpus: usize);

    /// Hand the boot CPU to the scheduler. Never returns.
    fn enter_scheduler(&self, hart_id: usize) -> !;

    // ── Secondary-CPU bring-up, in the order the shared
    // `secondary_main` (kernel/src/boot/smp.rs) calls them, after it has set
    // the per-CPU base, parked a CPU outside the possible mask and brought
    // up the tracer; before it unmasks interrupts.

    /// Join whatever set a TLB shootdown scans (riscv64: the SBI remote-fence
    /// hart set; nothing where invalidation is a hardware broadcast).
    fn secondary_tlb_online(&self, cpu: usize);

    /// This CPU's interrupt controller state and the sources it takes: the
    /// IPI, the timer, external lines (PLIC/AIA context, GIC redistributor,
    /// LAPIC).
    fn secondary_irq_init(&self, cpu: usize);

    /// Arm this CPU's first tick.
    fn secondary_timer_init(&self, cpu: usize);

    /// Publish this CPU as online for the boot CPU's readback, if the ISA's
    /// `wake_secondaries` waits for one. Called with interrupts still masked:
    /// a tick taken after `enable_all` may dispatch this CPU's idle task and
    /// never return here.
    fn secondary_publish_online(&self, cpu: usize);

    /// `(tick count, monotonic ms)` for the vDSO page the idle task refreshes
    /// on every wake, or `None` while the timebase is unknown or there is no
    /// vDSO.
    fn vdso_clock(&self) -> Option<(u64, u64)>;
}
