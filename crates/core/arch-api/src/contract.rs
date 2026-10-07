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

/// What the firmware table says about RAM and CPUs, in the shape the generic
/// early boot (`boot::early_main`) consumes. Produced by
/// [`ArchEntry::firmware_memory`] from the ISA's own parsed table.
#[derive(Clone, Copy, Debug)]
pub struct FirmwareMemory {
    /// First byte of RAM (physical).
    pub mem_start: usize,
    /// Bytes of RAM from `mem_start`.
    pub mem_size: usize,
    /// `true` when `mem_start`/`mem_size` came from the table, `false` for
    /// the platform fallback (no table, or one without a usable memory node).
    pub from_firmware: bool,
    /// CPUs the table lists (0: none listed).
    pub cpu_count: usize,
    /// The boot CPU's logical id.
    pub boot_cpu: usize,
    /// Where `cpu_count` came from ("DTB", "none"), for the boot log.
    pub cpu_source: &'static str,
}

/// The kernel boot sequence, per ISA (see the module doc for why the kernel,
/// not the ISA crate, implements it).
///
/// The generic early boot (`boot::early_main`, kernel/src/boot/early.rs)
/// owns the common steps, their order and their log lines, and calls the
/// early-boot hooks below at the points where the ISAs differ, in the order
/// they are declared here. Every hook is required (no default), so a new ISA
/// cannot leave a step out silently.
pub trait ArchEntry {
    /// The ISA's view of the firmware table, handed back to the probe hooks.
    type Firmware;

    /// The parsed device tree `early_main` hands `firmware_table` (the
    /// kernel's `azos_dtb::DtbInfo` on every ISA; `None` without one).
    type DeviceTree;

    /// The device-tree interrupt controller whose trigger types ring-3 lines
    /// take (`azos_dtb::IrqController`), and the triggers read for it
    /// (`azos_dtb::IrqTriggers`).
    type IrqController;
    /// See [`ArchEntry::IrqController`].
    type IrqTriggers;

    /// The page-table format, for the `[MM] Initializing VMM (...)` line.
    const PAGE_TABLES: &'static str;

    /// Before the console exists: state that must be read before the first
    /// lock is taken (aarch64: `SCTLR_EL1`, proof the MMU is on before the
    /// first atomic).
    fn pre_console(&self);

    /// The trap vector and the interrupt stacks it runs on, before any code
    /// that can fault (riscv64: `stvec`; aarch64 and x86_64 install theirs
    /// in assembly before Rust).
    fn trap_init(&self);

    /// The boot banner and the ISA's entry facts (CPU id, firmware pointer,
    /// exception level, self-checks that need only the console).
    fn boot_banner(&self, hart_id: usize, fw_table: usize);

    /// Report the firmware table at `fw_table` (`dt`: its device tree, as
    /// `early_main` parsed it) and keep what the probes need.
    fn firmware_table(&self, hart_id: usize, fw_table: usize, dt: Option<Self::DeviceTree>)
        -> Self::Firmware;

    /// Choose the interrupt controller the table describes (riscv64: PLIC or
    /// AIA) and bind the table's devices.
    fn irqchip_probe(&self, fw: &Self::Firmware);

    /// Choose the timer the table describes and check its frequency.
    fn timer_probe(&self, fw: &Self::Firmware);

    /// The CPU extensions the table declares, each confirmed on this CPU
    /// before it is used (riscv64: Zicboz, the vDSO hwcaps).
    fn cpu_features(&self, fw: &Self::Firmware);

    /// RAM and CPUs from the table, or the platform fallback.
    fn firmware_memory(&self, fw: &Self::Firmware) -> FirmwareMemory;

    /// The interrupt controller whose ring-3 trigger types `early_main`
    /// reads from the device tree, or `None` when none takes a trigger.
    fn irq_trigger_controller(&self) -> Option<Self::IrqController>;

    /// Record and report the trigger types read for ring-3 lines (`None`:
    /// the device tree describes none).
    fn irq_triggers(&self, triggers: Option<Self::IrqTriggers>);

    /// The last use of the firmware table before the page allocator owns
    /// RAM: report the choices made from it (`num_cpus` is the discovered
    /// CPU count).
    fn firmware_done(&self, fw_table: usize, num_cpus: usize);

    /// Keep the firmware table's own pages out of the page allocator, where
    /// the loader put it inside managed RAM.
    fn reserve_firmware_table(&self, fw_table: usize);

    /// The platform's device windows `(base, bytes)` beyond the console:
    /// interrupt controller, timer block, board devices. `early_main` maps
    /// them into the kernel table before it goes live.
    fn kernel_mmio_windows(&self) -> impl Iterator<Item = (usize, usize)>;

    /// Right after the kernel table went live (`vmm::enable_paging`): report
    /// it and publish what secondary CPUs attach.
    fn mmu_enabled(&self);

    /// After W^X/NX: take RAM out of the half of the address space user
    /// tables share (aarch64: TTBR0 keeps device windows only).
    fn restrict_low_half(&self);

    /// Read the null and stack guards back from the page table, and the
    /// ISA's opt-in access probes.
    fn verify_guards(&self);

    /// After the heap: the ISA's allocator self-checks and audit logs.
    fn post_heap(&self, heap_start: usize, kernel_end_aligned: usize);

    /// The timebase the vDSO page publishes, in Hz (riscv64: the fixed
    /// `TIMER_FREQ`; aarch64: `CNTFRQ_EL0`, read live).
    fn timebase_hz(&self) -> u64;

    /// The boot CPU's interrupt controller (PLIC/AIA, GIC), mapped and
    /// initialised; interrupts are still masked at the CPU.
    fn irqchip_init(&self, hart_id: usize, fw_table: usize);

    /// Unmask the interrupt classes the boot CPU takes before the console
    /// line is wired (riscv64: external + software; aarch64 waits for its
    /// timer).
    fn irq_enable_early(&self);

    /// Wire the console's receive/transmit interrupt.
    fn console_irq(&self, hart_id: usize, fw_table: usize);

    /// What a line's last ring-3 binding releases into at task exit.
    fn line_release(&self) -> fn(u32);

    /// Routing state for ring-3 lines and message-signalled interrupts
    /// (riscv64: the boot hart; aarch64: the ITS).
    fn irq_routing_init(&self, hart_id: usize);

    /// How secondary CPUs are started (aarch64: the PSCI conduit).
    fn smp_probe(&self, fw_table: usize);

    /// The boot CPU's timer: frequency check, the first tick where this ISA
    /// arms it during boot.
    fn timer_init(&self);

    /// Boot self-tests that need interrupts live.
    fn boot_selftests(&self);

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
