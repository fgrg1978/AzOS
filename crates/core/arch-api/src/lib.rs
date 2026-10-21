// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cross-ISA arch trait surface.
//!
//! This crate defines **what** the kernel needs from any
//! architecture, not **how** any specific architecture provides
//! it. By the modular pattern, every ISA ships an impl
//! crate (e.g. `azos_arch_riscv64`, `azos_arch_aarch64`,
//! `azos_arch_x86_64`) that satisfies these traits.
//!
//! # Why this crate
//!
//! Without a trait surface between "what the kernel asks" and "what an ISA
//! provides", every consumer grows `cfg(target_arch = "...")` branches.
//!
//! # Scope
//!
//! `crates/core/arch-riscv64`, `crates/core/arch-aarch64` and
//! `crates/core/arch-x86_64` implement this surface, and `azos_kernel` runs on
//! all three ISAs against it. Most call sites, however, still reach the ISA
//! crate directly through the `azos_arch` facade's re-exported modules
//! (`cpu::`, `mmu::`, ...) rather than through these traits; see
//! `crates/core/arch/src/lib.rs` for the measured count. This trait surface
//! does not close that gap by existing; the routing cleanup does.
//!
//! # The six trait families
//!
//! Worked through by grepping every `azos_arch::*` reference
//! across `crates/` and `kernel/`:
//!
//! | Family       | Captures                                           |
//! |--------------|----------------------------------------------------|
//! | [`Cpu`]      | hart id, wfi, halt, number of harts                |
//! | [`Interrupts`] | enable/disable all, timer deadline, IPI send      |
//! | [`Mmu`]      | PAGE_SIZE, map/unmap, switch_pt, TLB shootdown     |
//! | [`Boot`]     | platform shutdown / reboot / hart start            |
//! | [`Vector`]   | optional SIMD kernels (RVV / SVE / AVX2 / fallback)|
//! | [`SpinWait`] | cpu_relax, wait_while, CAS (Zawrs/Zacas, LSE+WFE, WAITPKG) |
//!
//! ISA-specific surfaces (CSR bit layout, PMP regions, SBI HSM
//! call numbers) stay private to each impl crate; they don't
//! belong in a cross-ISA API.

#![no_std]

// ──────────────────────────────────────────────────────────────────────────
// Cpu
// ──────────────────────────────────────────────────────────────────────────

/// Per-hart / per-core / per-thread identity + low-level halt.
///
/// `hart_id()` is the LOGICAL CPU id on every ISA: dense, the boot CPU is 0,
/// read from the register the boot code parks it in (`tp` on RISC-V,
/// `TPIDR_EL1` on aarch64, `%gs:0` on x86). It is not the hardware's own
/// number (`mhartid`, the MPIDR affinity, the APIC ID), which the firmware,
/// the interrupt controllers and the IPI paths need: `azos_percpu::hw_id`
/// maps one to the other, and only those boundaries translate. The kernel
/// uses `hart_id()` to index per-CPU statics — distinct cores return
/// distinct values in `0..nr_cpu_ids`.
///
/// **Note on `num_harts`**: deliberately NOT in this trait. The
/// number of available harts is a *platform discovery* fact (FDT
/// on RISC-V, ACPI MADT on x86, device tree on aarch64) — not
/// an ISA fact. The kernel reads it once at boot from the
/// appropriate platform interface and stores it; arch impls
/// should not duplicate that logic.
pub trait Cpu: Send + Sync {
    /// Identifier of the calling hart / core. Stable for the
    /// lifetime of the kernel.
    ///
    /// The id names the hart that ran this call, not the one the caller will
    /// run on: with interrupts on, a tick can move the task right after it.
    /// Reading it and then indexing a per-hart table is safe only with
    /// interrupts (or preemption) off across the pair, or when a stale id is
    /// harmless; the host lint `percpu_window` (sched-policy-tests) holds the
    /// scanned crates to that, with a `percpu-hint:` comment naming the reason
    /// where it is the second.
    fn hart_id(&self) -> usize;

    /// Wait For Interrupt — low-power idle. Returns when any
    /// pending interrupt is delivered to this hart.
    fn wfi(&self);

    /// Idle the calling hart in the idle state of index `depth` and return
    /// how long it slept, in microseconds, measured from entry to the
    /// instruction after the wake-up.
    ///
    /// The one idle seam: the idle task asks the energy governor for a depth
    /// (`azos_energy::IdleChoice`), the kernel passes it here. `depth` 0 is
    /// [`Self::wfi`]; a depth `d >= 1` is the `d`-th state of the platform's
    /// idle-state table, shallowest first. aarch64 and riscv64 take the table
    /// from the device tree's `cpu-idle-states` and enter a state with PSCI
    /// `CPU_SUSPEND` / SBI HSM `hart_suspend`: a standby or retention state
    /// returns as a `wfi` does; a power-down (aarch64) or non-retentive
    /// (riscv64) state loses the CPU's context, so the CPU keeps it first
    /// (callee-saved registers, stack pointer, translation state), the
    /// firmware resumes it at the secondary entry and the kernel restores it
    /// before this returns (Kconfig `CPU_IDLE_POWERDOWN`; the energy model
    /// marks such states `loses_context` and a CPU with real-time state is
    /// never given one). x86_64 builds the table from CPUID: depth 0 is `hlt`
    /// and depths 1.. are the `mwait` C-states of the per-model ladder (Intel's
    /// table; AMD and Hygon have the one `mwaitx` C1 state, their deeper
    /// states being ACPI I/O reads that are not read), which keep the
    /// architectural state in hardware, a depth past the cap the boot set
    /// from the model's latencies being the deepest state allowed. With no
    /// ladder (a model with no table, a hypervisor without `mwait`) or `IF`
    /// clear, every depth is `hlt`. A
    /// state the CPU cannot enter (no suspend parameter, `local-timer-stop`, a
    /// power-down state with no resume entry set) is entered as the deepest
    /// one below it, else as the shallow wait (`wfi` / `hlt`). The return
    /// value is what the governor learns from, so it is measured whatever the
    /// depth. Like `wfi`, it returns when any interrupt is pending.
    fn cpu_idle(&self, depth: u8) -> u64;

    /// Park this hart forever (used in panic-handler paths). Does
    /// not return.
    fn halt(&self) -> !;

    /// Read the monotonic tick counter.
    ///
    /// Owner decision 2026-09-20. Units are platform-defined and the kernel
    /// only needs monotonicity — the same contract
    /// [`Interrupts::set_timer_deadline`] states, and deliberately the same
    /// timebase, so a deadline can be computed from a reading without a
    /// conversion that only one ISA would get right.
    ///
    /// # Why this is here and not in a timer driver
    ///
    /// `Interrupts` used to carry a note saying `now_ticks` belonged to the
    /// timer driver, "CLINT on RISC-V, generic timer on aarch64". The premise
    /// was false in this tree: `clint::get_time()` is a bare `rdtime`, an ISA
    /// instruction, not an access to the CLINT's MMIO at all — and the
    /// aarch64 equivalent, `CNTVCT_EL0`, is an `mrs`. Both are exactly what
    /// `arch` owns.
    ///
    /// The cost of the old placement was measurable: of 385 `clint::`
    /// references in the tree, **129 are `get_time`** — every one of them a
    /// clock read with no portable name, and every one a blocker for building
    /// this kernel on aarch64.
    ///
    /// **Monotonic, never wall-clock.** Nothing here is steered by NTP or an
    /// RTC; a caller that needs a date wants `azos_net::ntp`, not this.
    /// The counter's epoch is reset-time and comparing readings across a
    /// reboot is meaningless.
    fn now_ticks(&self) -> u64;

    // ── Per-CPU base register (wave 15, NRCPUS) ─────────────────────────
    //
    // The register the kernel keeps per CPU and never lets ring 3 change
    // under it: `tp` on riscv64 (rebuilt on every trap from U-mode),
    // `TPIDR_EL1` on aarch64, the GS base on x86_64. What this kernel keeps
    // there is the CPU id, the index of this CPU's slot in every per-CPU
    // table (`azos_percpu`); a port that keeps an area pointer instead
    // changes these two methods and `azos_percpu`'s accessor, nothing else.

    /// The calling CPU's per-CPU base: today its CPU id, `0..NR_CPUS`.
    fn percpu_base(&self) -> usize;

    /// Set the calling CPU's per-CPU base. Boot and secondary bring-up only,
    /// before anything reads it on this CPU.
    fn set_percpu_base(&self, base: usize);

    // ── Resource-partition tag (QoS) ────────────────────────────────────
    //
    // Every memory request a hart issues can carry a small id that a
    // cache/bandwidth controller uses to apportion capacity and that
    // monitoring counters group by. The scheduler sets it on a context
    // switch from the incoming task's Domain `partition_id` (its topology
    // task row's `partition_id`; `azos_sched::qos`). One shape for every
    // ISA; the default bodies answer "no such hardware", so a port that has
    // none implements nothing:
    //
    // | ISA     | mechanism                          | partition id is      | Kconfig      |
    // |---------|------------------------------------|----------------------|--------------|
    // | riscv64 | Ssqosid `srmcfg` (RCID and MCID)   | RCID, 12 bits        | RV_SSQOSID   |
    // | aarch64 | MPAM `MPAM1_EL1` (PARTID)          | PARTID (later)       | (later)      |
    // | x86_64  | RDT `IA32_PQR_ASSOC` (CLOS)        | CLOS (later)         | (later)      |

    /// The highest partition id this hart can tag with; `0` when it cannot
    /// tag at all (the ISA has no mechanism, the hart lacks it, or Kconfig
    /// says `n`). Constant after the boot has probed it, so the switch path
    /// reads it to skip everything else. A partition id above it does not
    /// fit the hardware field: it must not be passed to [`Self::set_qos_tag`]
    /// (a masked write would alias another partition).
    fn qos_max_partition(&self) -> u16 {
        0
    }

    /// Make `partition` (`0` is the default partition) the tag of every
    /// memory request this hart issues from now on. `false`, and nothing
    /// written, when [`Self::qos_max_partition`] is below `partition`.
    fn set_qos_tag(&self, _partition: u16) -> bool {
        false
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Interrupts
// ──────────────────────────────────────────────────────────────────────────

/// Cross-ISA interrupt control + per-hart timer scheduling.
///
/// Only the *kernel's* notion of interrupt enable is exposed — the
/// individual interrupt-controller programming (PLIC vs GIC vs
/// I/O-APIC) lives in driver code, not here.
///
/// **Note on `now_ticks`**: it lives on [`Cpu`], not here — see that
/// method for why. This note used to say it was NOT in the trait surface at
/// all, because reading the counter was "the timer-driver's job". That was
/// wrong about this tree: the RISC-V read is a bare `rdtime` and the aarch64
/// one an `mrs CNTVCT_EL0`, both ISA instructions. Corrected 2026-09-20.
/// Programming the next deadline stays here, because that genuinely does go
/// through SBI / the generic timer / the APIC.
pub trait Interrupts: Send + Sync {
    /// Disable all maskable interrupts on the calling hart;
    /// returns the previous enable state (caller restores via
    /// [`Self::restore`]).
    fn disable_all(&self) -> InterruptState;

    /// Restore the interrupt-enable state previously returned by
    /// [`Self::disable_all`].
    ///
    /// **Only the enable state.** An impl must not write back any other
    /// architectural state it happened to capture alongside it. On aarch64
    /// that is automatic — `DAIF` holds nothing but the masks. On RISC-V it
    /// is not: `sstatus` also carries `SPIE`, `SPP`, `FS`, `SUM` and `MXR`,
    /// so a blanket write-back of the saved word reverts whatever else
    /// changed while interrupts were off. The RISC-V impl did exactly that
    /// until 2026-09-21; it is a read-modify-write of `SIE` alone now, which
    /// is what this sentence always promised and what the hand-written
    /// call sites in `sched`/`sync` were already doing.
    fn restore(&self, prev: InterruptState);

    /// Enable maskable interrupts on the calling hart, unconditionally.
    ///
    /// Not the inverse of [`Self::disable_all`] — that pair is for nesting,
    /// this is for the boot path and for a hart that is deliberately opening
    /// up (`kernel/src/main.rs` does it twice). Kept separate so a caller
    /// cannot reach for `restore` with a fabricated token to mean "on".
    fn enable_all(&self);

    /// Whether maskable interrupts are currently enabled on this hart.
    ///
    /// A query, for assertions and preemption audits — `crates/core/sync`'s
    /// `preempt` uses it to tell "we are inside a critical section" from
    /// "we are not". It reads live state; the token from
    /// [`Self::disable_all`] describes the state *before* the disable and
    /// cannot answer this.
    fn interrupts_enabled(&self) -> bool;

    /// Program the next per-hart timer interrupt to fire at
    /// absolute `deadline_ticks`. Tick units are platform-defined
    /// (mtime on RISC-V, generic timer on aarch64, APIC timer on
    /// x86) — the kernel only needs monotonicity.
    fn set_timer_deadline(&self, deadline_ticks: u64);

    /// Send an Inter-Processor Interrupt to the target hart.
    fn send_ipi(&self, target_hart: usize);
}

/// Opaque previous-state token returned by
/// [`Interrupts::disable_all`]. ISA-specific layouts go in the
/// impl crate; consumers treat it as a transparent token.
#[derive(Clone, Copy, Debug)]
pub struct InterruptState(pub u64);

/// Microseconds in `ticks` of a clock running at `hz` (0 if `hz` is 0). The
/// conversion every ISA's [`Cpu::cpu_idle`] reports its sleep through, in
/// 128-bit arithmetic so a long sleep at a fast clock does not wrap.
#[inline]
pub fn ticks_to_us(ticks: u64, hz: u64) -> u64 {
    if hz == 0 {
        return 0;
    }
    ((ticks as u128 * 1_000_000) / hz as u128).min(u64::MAX as u128) as u64
}

// ──────────────────────────────────────────────────────────────────────────
// Mmu
// ──────────────────────────────────────────────────────────────────────────

// The base page (translation granule) is a build-time choice. RISC-V Sv39
// has one base page, 4 KiB; aarch64 VMSAv8-64 has three granules and Kconfig
// `AARCH64_PAGE_4K` / `_16K` / `_64K` (config/Kconfig.arch) picks one. The
// choice reaches this crate as a cargo feature (`page-16k`, `page-64k`;
// neither = 4 KiB) emitted by `tools/kconfig_to_cargo.py` and forwarded by the
// kernel crate. `azos_limits::PAGE_SHIFT` carries the same choice from
// `.config`, and the kernel asserts at compile time that the two agree, so a
// build whose features and `.config` disagree does not compile.
#[cfg(all(feature = "page-16k", feature = "page-64k"))]
compile_error!("azos_arch_api: `page-16k` and `page-64k` select two granules; enable at most one");

/// log2 of [`PAGE_SIZE`]: 12 (4 KiB, the default and RISC-V's only base
/// page), 14 with feature `page-16k`, 16 with feature `page-64k`.
pub const PAGE_SHIFT: usize = if cfg!(feature = "page-64k") {
    16
} else if cfg!(feature = "page-16k") {
    14
} else {
    12
};

/// Page size in bytes: the translation granule this build was configured
/// for (see [`PAGE_SHIFT`]). Kept as a free constant, not a per-ISA trait
/// item, because code that only needs a page size (e.g. `crates/core/mm`'s
/// `wx` module) should not have to name a concrete ISA type or import the
/// trait to get it. [`Mmu::PAGE_SIZE`] still exists for code that is already
/// generic over an `M: Mmu`.
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;

/// A zero-sized type aligned to [`PAGE_SIZE`]. `#[repr(align(N))]` needs a
/// literal, so a static that must start on a page boundary (a page table, a
/// kernel stack whose bottom page is unmapped as a guard) carries a
/// `[PageAlign; 0]` field instead of writing `align(4096)` and silently
/// becoming sub-page-aligned under a larger granule.
#[cfg_attr(not(any(feature = "page-16k", feature = "page-64k")), repr(C, align(4096)))]
#[cfg_attr(feature = "page-16k", repr(C, align(16384)))]
#[cfg_attr(feature = "page-64k", repr(C, align(65536)))]
#[derive(Clone, Copy, Debug, Default)]
pub struct PageAlign;

const _: () = assert!(core::mem::align_of::<PageAlign>() == PAGE_SIZE);

/// Cross-ISA virtual-memory operations: page-table *entry encoding* for a
/// level-aware, multi-level radix tree.
///
/// # Design (owner decision, B2 — page-table abstraction)
///
/// `crates/core/mm` owns the page-table WALK (allocating tables, deciding when
/// to split a superpage, COW/demand-paging policy); `arch` owns only the
/// architectural *encoding* of one table entry — what bit pattern makes a
/// word valid, a table pointer, or a leaf, and what physical address and
/// permissions a given word carries. That split is why every method below
/// takes or returns a raw `u64` "word" plus a `level`, never a `Pte`
/// struct: a `Pte` type is a RISC-V Sv39 (or a VMSAv8) fact, and mm must
/// stay ISA-neutral.
///
/// **Why `is_leaf`/`is_table` take a `level` and RISC-V mostly ignores it.**
/// On Sv39 a leaf is any valid PTE with R|W|X set, AT ANY LEVEL — the
/// level is irrelevant to the leaf/table distinction. On VMSAv8-64 (4 KiB
/// granule) bits `[1:0]` mean different things at different levels:
/// `0b11` is a TABLE descriptor at L1/L2 but a PAGE (leaf) descriptor at
/// L3; `0b01` is a BLOCK (leaf) descriptor at L1/L2 and reserved at L3.
/// A same-named `is_leaf(word)` with no level parameter would be dishonest
/// on aarch64 — leafness genuinely depends on where in the tree you are.
///
/// **Level numbering.** Trait level `0` is the leaf level (4 KiB pages) —
/// RISC-V Sv39 `L0`, aarch64 VMSAv8-64 `L3`. Level `LEVELS - 1` is the
/// root — Sv39 `L2`, aarch64 `L1`. This matches `crates/core/mm`'s existing
/// `(0..3).rev()` / `(1..=2).rev()` walk loops, which already number
/// RISC-V levels this way; aarch64's impl maps trait level `l` to ARM
/// level `3 - l`.
///
/// **Modify, don't re-encode.** COW-breaking, demand-paging
/// materialization, `add_user_leaf_perms`'s permission widening and
/// `split_mega_range`'s flag carry-down all mutate an *existing* word
/// (flip one bit, keep the rest — including bits [`Self::pte_make_leaf`]
/// never set, like the A/D-preset convention or a software marker this
/// trait doesn't know about). So besides the constructors there are
/// narrow bit-level modifiers (`pte_share_cow` / `pte_break_cow`) rather
/// than a decode-then-re-encode round trip, which on RISC-V would lose
/// whatever convention a caller applied when it first built the word.
///
/// **The COW/DEMAND markers are mm's software convention, not hardware.**
/// RISC-V stores them in the PTE's RSW field (bits 8–9, architecturally
/// reserved for software). aarch64 has four software-defined bits at
/// `[58:55]` (Arm ARM §D8.3) for the same purpose. Neither ISA's MMU
/// reads them; they exist so mm can tell "this page is COW-shared" or
/// "this VA is demand-reserved" apart from every other invalid/valid
/// state, and both ISAs have room for the two-bit space mm needs.
///
/// **The page markers ([`PageMarker`]) use the same seam, on an invalid
/// word.** A word with `VALID = 0` is ignored whole by the walker, so the
/// marker flag, the kind and a 32-bit payload fit in the bits the hardware
/// does not read; [`Self::pte_marker`] tells such a word from an empty one, a
/// leaf or a demand reservation. A marker is only ever written over a leaf
/// the reclaimer owns, and cleared when the page is restored or its range
/// goes.
///
/// **`accessed`/`dirty` are request flags, not hardware facts.** Every ISA
/// supports software-managed A/D (the leaf encoders assume no `ADUE`/`HAFDBS`),
/// so a fresh leaf's A/D state is whatever the *caller* asks for via
/// [`PagePerms::accessed`] / [`PagePerms::dirty`] — matching what every
/// call site in this tree already does explicitly (e.g.
/// `PteFlags::USER_RW | PteFlags::ACCESSED | PteFlags::DIRTY`). RISC-V
/// honors the bits it is given; aarch64 always sets `AF` today (see
/// `arch-aarch64::mmu` for why unconditional AF does not change behavior
/// versus honoring the flag: every real call site already requests it).
pub trait Mmu: Send + Sync {
    /// Page size in bytes. See the free [`PAGE_SIZE`] constant for
    /// non-generic callers.
    const PAGE_SIZE: usize;

    /// Number of levels this ISA's default translation regime walks.
    /// `3` on both RISC-V Sv39 and aarch64 VMSAv8-64 (4 KiB granule,
    /// `T0SZ = 25` → 39-bit input range, the config `arch-aarch64`
    /// programs at boot).
    ///
    /// A method, not an associated const: `crates/core/mm` reaches the active
    /// ISA only through the `ARCH` singleton *value* the facade exports
    /// (`azos_arch::ARCH`), never by naming `Riscv64`/`Aarch64`
    /// directly — that is the whole point of going through the facade.
    /// An associated const needs `<ConcreteType as Mmu>::LEVELS`, which
    /// would force mm to name the concrete type after all. `#[inline]`
    /// on both impls makes this compile to the same immediate an
    /// associated const would.
    fn levels(&self) -> usize;

    /// Entries per table. `512` on both ISAs at 4 KiB granule (9 VPN
    /// bits per level); `PAGE_SIZE / 8` in general (2048 at 16 KiB, 8192 at
    /// 64 KiB on aarch64). See [`Self::levels`] for why this is a method.
    fn entries_per_table(&self) -> usize;

    /// Entries the ROOT table actually indexes. Equal to
    /// [`Self::entries_per_table`] where the input range fills the root
    /// (Sv39; aarch64 4 KiB granule, 39-bit). Smaller where it does not:
    /// aarch64 16 KiB granule at 39 bits indexes 8 root slots, 64 KiB at 48
    /// bits 64. A walk over every root slot uses this bound; the rest of the
    /// root frame is never read by the hardware.
    fn root_entries(&self) -> usize { self.entries_per_table() }

    /// The index into the table at `level` that `va` selects.
    fn vpn(&self, va: usize, level: usize) -> usize;

    /// The empty (all-zero / invalid) word — an unmapped slot.
    fn pte_empty(&self) -> u64;

    /// Is `word`'s valid bit set? True for both table and leaf entries.
    fn pte_is_valid(&self, word: u64) -> bool;

    /// Is `word`, read AT `level`, a pointer to the next-level table?
    fn pte_is_table(&self, word: u64, level: usize) -> bool;

    /// Is `word`, read AT `level`, a leaf (maps a page/block/gigapage)?
    fn pte_is_leaf(&self, word: u64, level: usize) -> bool;

    /// The physical address `word` encodes — the next-level table's base
    /// for a table entry, or the mapped frame's base for a leaf.
    fn pte_phys(&self, word: u64) -> usize;

    /// Build a non-leaf descriptor pointing at the table based at `pa`.
    fn pte_make_table(&self, pa: usize) -> u64;

    /// Build a fresh leaf descriptor for `pa`, valid when read AT `level`,
    /// carrying `perms`. Returns `Err` if `pa` is not page-aligned or
    /// `perms` is not representable on this ISA (e.g. aarch64 has no
    /// execute-only mapping).
    fn pte_make_leaf(&self, pa: usize, perms: PagePerms, level: usize) -> Result<u64, MmuError>;

    /// The leaf bit that makes a translation match under every ASID, as
    /// `crates/core/mm` ORs it into a kernel leaf of a kernel-only slot
    /// (riscv64 Sv39 G, Kconfig `RV_KERNEL_GLOBAL`). Not part of
    /// [`PagePerms`]: a re-encode through [`Self::pte_perms`] drops it, so
    /// `vmm` carries it over from the old word. `0`: the model does not use
    /// one here. aarch64 needs none (the kernel half is `TTBR1_EL1`, global
    /// by construction; user leaves carry nG); x86_64 `PG_GLOBAL` (bit 8)
    /// is the counterpart, not yet used for the kernel half.
    fn pte_global_bit(&self) -> u64 { 0 }

    /// Decode a leaf word's permissions. Level-independent: the
    /// attribute bits (R/W/X/U/mem/A/D) live in the same positions
    /// regardless of which level the leaf was found at.
    fn pte_perms(&self, word: u64) -> PagePerms;

    /// Is this word a valid leaf with the software COW marker set? A word that
    /// is not present is never COW: a page marker (`pte_make_marker`) reuses the
    /// software bits of a leaf, the COW position among them, so the flag is read
    /// only from a valid word, whatever the caller walked.
    fn pte_is_cow(&self, word: u64) -> bool;

    /// Mark a writable leaf as COW-shared: clear WRITE, set the COW
    /// marker. Used by `fork()` on both the parent's and the child's PTE.
    fn pte_share_cow(&self, word: u64) -> u64;

    /// Break a COW-shared leaf after the private copy is made: clear the
    /// COW marker, set WRITE and DIRTY (the page was just written by the
    /// copy).
    fn pte_break_cow(&self, word: u64) -> u64;

    /// Build a demand-paging marker: `VALID = 0` (so any access traps),
    /// the software DEMAND marker set, and `perms` stored inline so
    /// [`Self::pte_demand_perms`] can recover them when the fault fires.
    fn pte_make_demand(&self, perms: PagePerms) -> u64;

    /// Is `word` a demand-paging marker (invalid, DEMAND-marked)?
    fn pte_is_demand(&self, word: u64) -> bool;

    /// Recover the `perms` stored in a demand marker built by
    /// [`Self::pte_make_demand`].
    fn pte_demand_perms(&self, word: u64) -> PagePerms;

    /// Build a not-present *page marker*: `VALID = 0` (any access traps), the
    /// software marker flag set, `kind` and a 32-bit `payload` stored inline.
    /// It is the word the reclaimer leaves in a user page's slot while the
    /// page is in the compressed pool or on swap ([`PageMarker`]), so a fault
    /// reads where the contents are instead of finding an empty slot and
    /// zero-filling. Never read as a demand marker ([`Self::pte_is_demand`]
    /// is false for it) and never as a COW leaf.
    fn pte_make_marker(&self, kind: PageMarker, payload: u32) -> u64;

    /// The kind and payload of a page marker built by
    /// [`Self::pte_make_marker`]; `None` for any other word (empty, valid,
    /// demand).
    fn pte_marker(&self, word: u64) -> Option<(PageMarker, u32)>;

    /// Switch the current address space to `root_phys` (page
    /// table root physical address). The ASID slot is provided
    /// separately so the impl can re-use it for TLB tagging.
    fn switch_pt(&self, root_phys: usize, asid: u16);

    /// Activate the KERNEL's own page table.
    ///
    /// Separate from [`Self::switch_pt`] because the two are the same register on
    /// one ISA and different registers on the other, and conflating them was
    /// a real bug: on aarch64 the kernel's table lives in `TTBR1_EL1` (the
    /// upper half) while every task switch rewrites `TTBR0_EL1` (the lower
    /// half), so a kernel table activated through `switch_pt` would be
    /// replaced by the next user task and the kernel would run on whatever
    /// address space that task happened to have. On riscv64 both halves live
    /// in `satp`, so this is `switch_pt` with the kernel's ASID and the
    /// implementation says so rather than pretending to be different.
    ///
    /// Called once at boot, after the kernel's mappings are built.
    fn switch_kernel_pt(&self, root_phys: usize);

    /// Invalidate the entire TLB. Used on PT teardown.
    fn flush_tlb_all(&self);

    /// Invalidate TLB entries tagged with `asid`. Used on
    /// per-task address-space tear-down to avoid blowing away
    /// other tasks' translations.
    fn flush_tlb_asid(&self, asid: u16);

    /// ASID bits this hart's MMU implements (0: none). Boot only, with the
    /// MMU on. riscv64 probes satp.ASID (ASIDLEN); aarch64 reads
    /// ID_AA64MMFR0_EL1.ASIDBits. The default is an ISA without ASIDs.
    fn asid_bits(&self) -> u32 { 0 }

    /// Does turning a table entry into a block (or a block into a table) at
    /// one translation level need break-before-make: the old entry made
    /// invalid and its translations flushed on every CPU that may hold them,
    /// before the new one is installed? Without it the TLB may hold both the
    /// block and entries of the old table, and the CPU may raise a TLB
    /// conflict abort. aarch64: `true` unless every CPU reports
    /// ID_AA64MMFR2_EL1.BBM >= 2 (FEAT_BBM level 2: the change is allowed in
    /// place and never aborts; Cortex-A53, A72 and A76 report 0); the answer
    /// is the weakest CPU's, noted as each comes up. RISC-V and x86 define no
    /// such abort for the same-map change the kernel makes: `false`, stated
    /// by each ISA. Read by the superpage promotion
    /// (`vmm::promote_user_block`), which does the break when this is `true`.
    fn block_change_needs_bbm(&self) -> bool;

    /// Pages in one contiguous run of level-0 leaves, or 0: this ISA writes
    /// none (or the build or the CPU says no: Kconfig `A64_CONTIG_HINT` n,
    /// `RV_SVNAPOT` n or not found). aarch64: the contiguous hint, 16 pages
    /// at a 4 KiB granule (64 KiB), 128 at 16 KiB and 32 at 64 KiB (2 MiB
    /// both). riscv64: Svnapot, 16 pages (64 KiB). x86_64: 0, there is no
    /// equivalent below the 2 MiB leaf. See [`contig`].
    fn contig_run_pages(&self) -> usize { 0 }

    /// The word of member `index` of the run whose first frame is `run_pa`
    /// (aligned to the run's size), carrying `perms`. aarch64: each member
    /// names its own frame (`run_pa + index * PAGE_SIZE`) plus the hint bit;
    /// riscv64: every member is the same NAPOT word. `Err` when
    /// [`Self::contig_run_pages`] is 0 or `run_pa` is not aligned to the run.
    fn pte_make_contig_leaf(&self, run_pa: usize, index: usize, perms: PagePerms) -> Result<u64, MmuError> {
        let _ = (run_pa, index, perms);
        Err(MmuError::UnrepresentablePerms)
    }

    /// Is the level-0 leaf `word` a member of a contiguous run?
    fn pte_is_contig(&self, word: u64) -> bool { let _ = word; false }

    /// The plain 4 KiB word for member `index` of the run `word` belongs to
    /// (read from any slot of it): the same frame and attributes, no hint.
    /// What a break writes back into each slot.
    fn pte_contig_member(&self, word: u64, index: usize) -> u64 { let _ = index; word }

    /// Bytes the level-0 leaf `word` translates through [`Self::pte_phys`]:
    /// [`PAGE_SIZE`], except on riscv64 for a NAPOT word, whose PPN names the
    /// whole run (the offset is then taken modulo the run, not the page).
    fn pte_leaf0_span(&self, word: u64) -> usize { let _ = word; PAGE_SIZE }

    /// Invalidate the TLB entry (if any) translating `va`, on this hart only
    /// on riscv64 (aarch64's form is a broadcast). Used where a PTE change
    /// cannot leave another hart with a harmful stale entry: demand
    /// materialize and permission widening (a stale entry only faults and
    /// re-walks), and the kernel's own table at boot. Removals, downgrades and
    /// repoints of user PTEs (unmap, munmap, fork COW write-protect, COW
    /// break) use [`Self::tlb_shootdown`].
    fn flush_tlb_page(&self, va: usize);

    /// Cross-hart TLB shootdown: after the caller has REMOVED, DOWNGRADED or
    /// REPOINTED user PTEs of the table rooted at `root_phys`, invalidate
    /// `[va, va + len)` (`len == TLB_ALL`: everything) on every hart that may
    /// hold a translation for it, this one included, and return only when
    /// none can use one. Frames the old PTEs named may be freed after it
    /// returns, not before.
    ///
    /// Returns the mask of remote harts that had to be interrupted (riscv64:
    /// the SBI `remote_sfence_vma` hart mask; 0 when no IPI was sent, and
    /// always 0 on aarch64, where `TLBI ...IS` is a hardware broadcast).
    fn tlb_shootdown(&self, root_phys: usize, va: usize, len: usize) -> usize;

    /// Harts that still translate through the table rooted at `root_phys`,
    /// as a hart bit mask, this one included. A page table may be freed only
    /// while this is 0: a hart that still names the root walks frames the
    /// allocator is about to reissue, and when one of them comes back as
    /// someone else's page the walk fails on kernel text (the trap vector
    /// itself, in the one fault this was found by).
    ///
    /// riscv64: exact, from the `satp` every hart publishes before it
    /// installs one (`tlb::AZOS_HART_SATP`). aarch64: this PE's own
    /// `TTBR0_EL1` only, the one a free on the exit or exec path could still
    /// be running on; nothing publishes the other PEs' roots. That suffices
    /// because no other PE can hold a lived root when it is freed: the free
    /// waits for every other thread of the process to leave it
    /// (`group_exit`, `exec_end_other_threads`), and the slot-reuse reclaim
    /// only ever sees roots no PE installed (after boot).
    fn root_holders(&self, root_phys: usize) -> usize;

    // ── Page aging (MM-MGLRU): the Accessed bit ─────────────────────────

    /// The Accessed bit of a leaf word, in place (riscv64 A, bit 6; aarch64
    /// AF, bit 10; x86_64 A, bit 5). `0`: this model keeps none, and
    /// [`Self::harvest_accessed`] and [`Self::resolve_accessed_fault`] do
    /// nothing. Every real port overrides it.
    fn pte_accessed_bit(&self) -> u64 { 0 }

    /// A pointer to the 8-byte page-table word at physical address `pa`, in
    /// the address the kernel reads its own tables through: the identity on
    /// riscv64 and in a host build, `pa | KERNEL_VA_OFFSET` on aarch64,
    /// `pa + DIRECT_MAP_BASE` on x86_64 (the same offsets `mm::addr::phys_to_virt`
    /// adds; the aging walk is below `mm`, so it carries its own copy of the
    /// constant per ISA, read from the one place each ISA defines it).
    fn table_word(&self, pa: usize) -> *const core::sync::atomic::AtomicU64 {
        pa as *const core::sync::atomic::AtomicU64
    }

    /// Does this CPU set the Accessed bit itself when it translates through a
    /// leaf that has it clear? x86_64: always. riscv64: Svadu, found at boot
    /// and enabled by the firmware (Kconfig `RV_SVADU`). aarch64: FEAT_HAFDBS
    /// with `TCR_EL1.HA` set (Kconfig `A64_HAFDBS`).
    ///
    /// `false` is the software model: a leaf with A clear FAULTS on its next
    /// access (RISC-V Svade, an aarch64 Access Flag fault), and the page-fault
    /// path calls [`Self::resolve_accessed_fault`] (`vmm::handle_accessed_fault`,
    /// from `trap::fault::page_fault`) before it treats the
    /// fault as an error. Aging a page costs a fault there, a cost the
    /// scanner should weigh; with `true` it costs nothing.
    fn accessed_in_hardware(&self) -> bool { false }

    /// Clear-and-collect the Accessed bits of up to [`aging::HARVEST_MAX_PAGES`]
    /// pages from `va` (rounded down to a page) in the table rooted at
    /// `root_phys`: bit `i` of the result is set when the page at
    /// `va + i * PAGE_SIZE` was accessed since the last harvest, and its A is
    /// cleared. A page with no leaf, and a leaf that is not a user leaf, read
    /// as not accessed and are left alone.
    ///
    /// * A leaf larger than a page (a 2 MiB or 1 GiB block) has one A bit and
    ///   reports it for every page of the range it covers; so does a
    ///   contiguous run (aarch64 hint, riscv64 Svnapot), whose members are
    ///   read as one (A is the OR of the members', and cleared in all of
    ///   them, so the sixteen words stay equal). A caller that wants exact
    ///   per-page ages keeps blocks and runs out of the ranges it ages, or
    ///   aligns its ranges to their size.
    /// * The clear is an atomic read-modify-write on the word: a concurrent
    ///   hardware D update is not lost.
    /// * **No TLB flush.** A translation cached with A already set is not
    ///   written back when it is used again, so a page that stays in the TLB
    ///   looks idle until the entry goes. That is aging's usual
    ///   approximation (Linux skips the flush on x86 and arm64 for the same
    ///   reason); a cross-hart shootdown per harvest would cost more than the
    ///   accuracy buys.
    /// * The caller holds the address space against unmap, so the tables it
    ///   walks are not freed under it.
    ///
    /// This is the only reader of the Accessed bit outside the fault path.
    fn harvest_accessed(&self, root_phys: usize, va: usize, pages: usize) -> u64 {
        aging::harvest(self, root_phys, va, pages)
    }

    /// The software half of aging, for a CPU that does not set A itself
    /// ([`Self::accessed_in_hardware`] false): if the user leaf that maps `va`
    /// in the table rooted at `root_phys` has A clear, set it (every member
    /// of a contiguous run), invalidate this hart's entry for `va`, and return
    /// `true`: the access can be retried. `false`: there is no such leaf, so
    /// the fault is something else and keeps its other handling.
    ///
    /// The word is set by a compare-and-swap that re-checks it is still a
    /// valid user leaf, so a page unmapped meanwhile is not resurrected as a
    /// stray bit in an empty slot. A permission fault on a leaf whose A is
    /// also clear is "resolved" first and faults again with A set, which then
    /// returns `false`: one extra fault, no loop.
    fn resolve_accessed_fault(&self, root_phys: usize, va: usize) -> bool {
        aging::resolve(self, root_phys, va)
    }
}

/// `len` for [`Mmu::tlb_shootdown`] meaning "the whole address space".
pub const TLB_ALL: usize = usize::MAX;

/// The word a level-1 slot holds between the break and the make of a
/// break-before-make block change (`vmm::promote_user_block`): not valid on
/// any ISA (bit 0 clear, the hardware ignores the rest), not the empty word,
/// not a demand marker, so the hardware faults on the block and a page-table
/// walk in software knows to wait for the make instead of building a table
/// over it.
pub const PTE_BBM_PARK: u64 = 1 << 62;

/// How a mapping is cached and ordered, in the cross-ISA model.
///
/// - `WB`: normal write-back cacheable memory (RAM).
/// - `WC`: write-combining, uncached, weakly ordered, writes may merge
///   (a framebuffer). x86: PAT index 1. aarch64: Normal non-cacheable
///   (MAIR index 3). riscv64: Svpbmt `NC` when the extension was probed,
///   else the plain PMA type.
/// - `NC`: normal non-cacheable (a DMA buffer that must not be cached but
///   may be reordered). x86: PAT index 2 (UC-). aarch64: Normal
///   non-cacheable (MAIR index 2). riscv64: Svpbmt `NC` / plain.
/// - `Device`: strongly ordered, no merging or speculation (registers).
///   x86: PAT index 3 (UC). aarch64: Device-nGnRE. riscv64: Svpbmt `IO` /
///   plain.
///
/// On riscv64 `WC` and `NC` share one encoding (Svpbmt has a single
/// non-cacheable normal type), so a decoded leaf reports `NC`; x86 and
/// aarch64 give each its own PAT/MAIR index and round-trip exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemType {
    WB,
    WC,
    NC,
    Device,
}

/// What a not-present page marker ([`Mmu::pte_make_marker`]) says about a
/// user page the reclaimer took out of the address space.
///
/// The encoding lives in software bits of the invalid word, so the hardware
/// never reads it: RISC-V RSW bit 8 (with DEMAND, bit 9, clear), aarch64
/// software bit 57 (with DEMAND, bit 58, clear), x86-64 available bit 11 (with
/// DEMAND, bit 10, clear). The kind takes two more bits of the word and the
/// payload 32, in places each ISA's own `mmu` module documents. Only the
/// pager reads a payload: the architecture keeps it whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PageMarker {
    /// The page is in the compressed pool. The payload is the generation of
    /// the pool entry that holds it: the entry is found by the page's key and
    /// has to carry this generation, so a marker never restores the copy of
    /// an earlier or later store of the same page.
    Compressed = 1,
    /// As `Compressed`, and the entry's segment is on the swap area: a fault
    /// brings it back before it reads the entry.
    Swapped = 2,
    /// The reclaimer is storing the page right now: it is out of the table
    /// and not in the pool yet. A fault that finds this waits for the store
    /// to end, instead of zero-filling a page whose contents are in flight.
    InTransit = 3,
}

impl PageMarker {
    /// The two-bit code the ISA modules store; never 0.
    #[inline]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// The kind a stored code names (`None` for 0, which no marker carries,
    /// and for the unused code 4 and above).
    #[inline]
    pub const fn from_code(code: u8) -> Option<PageMarker> {
        match code {
            1 => Some(PageMarker::Compressed),
            2 => Some(PageMarker::Swapped),
            3 => Some(PageMarker::InTransit),
            _ => None,
        }
    }
}

/// Page permissions in the cross-ISA model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PagePerms {
    pub read:  bool,
    pub write: bool,
    pub exec:  bool,
    /// Userspace may access. False = kernel-only.
    pub user:  bool,
    /// Memory type: how the CPU caches and orders accesses. See [`MemType`]
    /// for the per-ISA encoding.
    pub mem: MemType,
    /// Pre-set the Accessed bit at creation time (both ISAs support
    /// software-managed A/D; this is a per-mapping request, not an ISA
    /// fact — see the [`Mmu`] trait doc).
    pub accessed: bool,
    /// Pre-set the Dirty bit at creation time. Same nature as `accessed`.
    pub dirty: bool,
}

impl PagePerms {
    /// Kernel R/W data; no exec. A+D preset (matches
    /// `PteFlags::KERNEL_RW`'s existing software-managed-A/D convention).
    pub const KERNEL_RW: Self = Self {
        read: true, write: true, exec: false, user: false, mem: MemType::WB,
        accessed: true, dirty: true,
    };
    /// Kernel code; R+X. A preset, no D (never written).
    pub const KERNEL_RX: Self = Self {
        read: true, write: false, exec: true, user: false, mem: MemType::WB,
        accessed: true, dirty: false,
    };
    /// Kernel R/O data (e.g. `.rodata`). A preset, no D.
    pub const KERNEL_RO: Self = Self {
        read: true, write: false, exec: false, user: false, mem: MemType::WB,
        accessed: true, dirty: false,
    };
    /// Kernel R/W/X — the coarse identity-map permission `vmm::init` uses
    /// before W^X is enforced section-by-section. A+D preset.
    pub const KERNEL_RWX: Self = Self {
        read: true, write: true, exec: true, user: false, mem: MemType::WB,
        accessed: true, dirty: true,
    };
    /// User R/W data; no exec. Perm bits only — callers that need A/D
    /// preset (every leaf-creating call site in this tree does) set
    /// `accessed`/`dirty` explicitly, e.g.
    /// `PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW }`.
    pub const USER_RW: Self = Self {
        read: true, write: true, exec: false, user: true, mem: MemType::WB,
        accessed: false, dirty: false,
    };
    /// User code; R+X.
    pub const USER_RX: Self = Self {
        read: true, write: false, exec: true, user: true, mem: MemType::WB,
        accessed: false, dirty: false,
    };
    /// User R/O data.
    pub const USER_RO: Self = Self {
        read: true, write: false, exec: false, user: true, mem: MemType::WB,
        accessed: false, dirty: false,
    };
    /// A device window mapped into a USER driver (`DOMAIN_MMIO_MAP`): R/W,
    /// uncached, never exec, A+D preset. `mmio_map_user` used `USER_RW`,
    /// which is `MemType::WB` — on aarch64 that is MAIR Normal write-back,
    /// so device registers could be speculatively read, merged and cached.
    /// riscv64 ignores the bit (PMAs decide), which is why nothing failed.
    pub const USER_MMIO_RW: Self = Self {
        read: true, write: true, exec: false, user: true, mem: MemType::Device,
        accessed: true, dirty: true,
    };
    /// Read-only user device window. Same reasoning as [`Self::USER_MMIO_RW`].
    pub const USER_MMIO_RO: Self = Self {
        read: true, write: false, exec: false, user: true, mem: MemType::Device,
        accessed: true, dirty: true,
    };
    /// MMIO region; uncached.
    pub const MMIO: Self = Self {
        read: true, write: true, exec: false, user: false, mem: MemType::Device,
        accessed: true, dirty: true,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmuError {
    /// `phys` was not page-aligned to [`Mmu::PAGE_SIZE`].
    NotAligned,
    /// Requested perms are not representable on this ISA (e.g.
    /// `exec + !read` which RISC-V allows but some ISAs don't).
    UnrepresentablePerms,
    /// `phys` is outside the platform's physical address range.
    BadPhys,
}

// ──────────────────────────────────────────────────────────────────────────
// Boot
// ──────────────────────────────────────────────────────────────────────────

/// Platform-level lifecycle: shut down the machine, reboot, and
/// bring secondary harts up.
pub trait Boot: Send + Sync {
    /// Stop the whole machine. Does not return.
    fn shutdown(&self) -> !;

    /// Reboot the whole machine. Does not return.
    fn reboot(&self) -> !;

    /// Start `hart_id` executing at `start_pc` with `opaque`
    /// passed in the first argument register. On RISC-V this maps
    /// to SBI HSM `hart_start`; on aarch64 to PSCI CPU_ON; on x86
    /// to APIC INIT/SIPI sequence.
    fn hart_start(
        &self,
        hart_id: usize,
        start_pc: usize,
        opaque: usize,
    ) -> Result<(), HartStartError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HartStartError {
    AlreadyOn,
    InvalidHartId,
    Denied,
    Other(i32),
}

// ──────────────────────────────────────────────────────────────────────────
// Vector (optional)
// ──────────────────────────────────────────────────────────────────────────

/// Optional SIMD kernels. ISA impls expose a fast path via
/// RVV / SVE / NEON / AVX2 / etc., plus a scalar fallback. The
/// kernel selects between them at boot via a feature flag or
/// CPUID-style probe.
///
/// Only the operations the kernel actually uses appear here — no
/// general-purpose matrix library. Today: the ML inner loops.
pub trait Vector: Send + Sync {
    /// Dot product of two equal-length `f32` slices. Returns the
    /// scalar fallback result if no SIMD is available.
    fn dot_f32(&self, a: &[f32], b: &[f32]) -> f32;

    /// `true` if the impl is actually using SIMD. Diagnostic — the
    /// kernel never branches on this.
    fn is_accelerated(&self) -> bool;
}

// ──────────────────────────────────────────────────────────────────────────
// Hypervisor (Kconfig VIRT)
// ──────────────────────────────────────────────────────────────────────────

/// Which hardware virtualization an ISA gives a monitor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HvKind {
    /// RISC-V H extension: VS-mode guests, G-stage tables (`hgatp`).
    RiscvH,
    /// ARMv8 EL2: EL1 guests, stage-2 tables (`VTTBR_EL2`).
    ArmEl2,
    /// AMD SVM: `VMRUN` with a VMCB, nested page tables.
    X86Svm,
    /// Intel VMX: `VMLAUNCH` with a VMCS, extended page tables.
    X86Vmx,
}

impl HvKind {
    /// The word the boot line prints.
    pub const fn name(self) -> &'static str {
        match self {
            HvKind::RiscvH => "riscv-h",
            HvKind::ArmEl2 => "arm-el2",
            HvKind::X86Svm => "x86-svm",
            HvKind::X86Vmx => "x86-vmx",
        }
    }
}

/// Whether this boot can host a guest. A CPU that cannot, or a policy that
/// says never, is *no hypervisor, with the reason*, never a boot failure
/// (Kconfig `require` refuses before this is asked).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HvStatus {
    Usable(HvKind),
    /// The reason, as the boot line prints it.
    Absent(&'static str),
}

/// What a stage-2 mapping lets the guest do. Read is implied by any grant: no
/// ISA has a write-only or execute-only guest page the monitor could use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StagePerms {
    pub write: bool,
    pub exec: bool,
}

impl StagePerms {
    /// Data.
    pub const RW: Self = Self { write: true, exec: false };
    /// Code.
    pub const RX: Self = Self { write: false, exec: true };
    /// Read only.
    pub const RO: Self = Self { write: false, exec: false };
}

/// How a guest access to guest-physical memory looked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageAccess {
    Read,
    Write,
    Exec,
}

/// Why a stage-2 operation refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageError {
    /// A guest-physical address beyond [`Hypervisor::gpa_bits`].
    OutOfRange,
    /// An address not aligned to a [`STAGE_PAGE`].
    Misaligned,
    /// The page is already mapped (or inside a larger mapping).
    Overlap,
    /// Nothing is mapped there.
    NotMapped,
    /// The table allocator is out of frames.
    NoMemory,
    /// The host-physical address is beyond what the ISA's tables can name.
    HostAddress,
}

/// The stage-2 page, in bytes. Every ISA maps the guest in 4 KiB units,
/// whatever the kernel's own `PAGE_SIZE` is.
pub const STAGE_PAGE: u64 = 4096;

/// Where stage-2 table pages live: the kernel lends frames and the entries'
/// words. Each ISA's table walker has its own memory trait (table and index,
/// entry address, one-page tables); the glue in `ext/hv` wraps this one into
/// it, so the code above the ISAs holds a single shape.
pub trait StageTableMem {
    /// `pages` contiguous zeroed frames aligned to `pages * 4096`; the
    /// host-physical address of the first.
    fn alloc(&mut self, pages: usize) -> Option<u64>;
    /// Give back what [`alloc`](Self::alloc) returned.
    fn free(&mut self, pa: u64, pages: usize);
    /// The 8-byte entry at host-physical `pa`.
    fn read(&self, pa: u64) -> u64;
    /// Store the 8-byte entry at host-physical `pa`.
    fn write(&mut self, pa: u64, word: u64);
}

/// One VM's stage-2 tables, as the ISA names them. Opaque to the code above:
/// `root` is the host-physical address of the root table, `aux` the ISA's
/// own shape word (the G-stage mode, the IPA width).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stage2Root {
    pub root: u64,
    pub aux: u64,
}

/// An emulated memory-mapped load or store the hardware decoded for the
/// monitor (RISC-V `htinst`, ARM `ESR_EL2.ISV`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioAccess {
    pub gpa: u64,
    /// Access width in bytes: 1, 2, 4 or 8.
    pub size: u8,
    pub write: bool,
    /// The guest register the value comes from (a store) or goes to (a load).
    pub reg: u8,
    /// Bytes of the instruction: how far to advance the guest PC once the
    /// access is emulated.
    pub insn_len: u8,
}

/// An x86 `IN`/`OUT` the permission map intercepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PioAccess {
    pub port: u16,
    pub size: u8,
    pub write: bool,
    pub string: bool,
    pub rep: bool,
}

/// Why a guest stopped, the same on every ISA. The monitor's loop and the
/// exit router switch on this and on nothing ISA-specific.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// An access the stage-2 tables refused and the hardware did not decode
    /// (x86 nested fault, an undecodable RISC-V or ARM abort, an instruction
    /// fetch): the monitor maps the page, hands the address to a device
    /// model, or kills the guest.
    Fault { gpa: u64, access: StageAccess },
    /// A decoded load or store, ready for a device model.
    Mmio(MmioAccess),
    /// An `IN`/`OUT` on an intercepted port.
    Pio(PioAccess),
    /// The guest called the monitor (SBI `ecall`, `HVC`/`SMC`, `VMMCALL`);
    /// the arguments are in its registers.
    Hypercall,
    /// x86 `CPUID`.
    Cpuid,
    /// A trapped system-register, CSR or MSR access.
    SysReg { write: bool },
    /// The guest waits for an interrupt (`wfi`, `wfe`, `hlt`).
    Wait,
    /// A physical interrupt arrived while the guest ran: the host takes it
    /// as soon as it re-enables interrupts, then re-enters.
    HostInterrupt,
    /// The guest stopped for good (x86 triple fault).
    Shutdown,
    /// Entry failed: the hardware refused the guest's control state.
    InvalidState,
    /// Anything else: the ISA's raw exit code.
    Other(u64),
}

/// A trap taken while a guest ran, as the ISA delivers it, undecoded. The
/// fields are the ISA's own trap registers in a fixed order:
///
/// | ISA     | `code`       | `info`                                  |
/// |---------|--------------|-----------------------------------------|
/// | riscv64 | `scause`     | `stval`, `htval`, `htinst`, `hstatus`   |
/// | aarch64 | `ESR_EL2` (or [`RAW_ARM_IRQ`] for a physical IRQ/FIQ vector) | `FAR_EL2`, `HPFAR_EL2` |
/// | x86_64  | SVM `EXITCODE` | `EXITINFO1`, `EXITINFO2`              |
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RawExit {
    pub code: u64,
    pub info: [u64; 4],
}

/// `RawExit::code` the aarch64 vector stub passes for a physical interrupt
/// taken while the guest ran (`ESR_EL2` is not written by an IRQ).
pub const RAW_ARM_IRQ: u64 = u64::MAX;

/// A decoded emulated MMIO access, completed: what the guest's load reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioDone {
    pub access: MmioAccess,
    /// The value a load returns (a store: 0).
    pub value: u64,
}

/// One vCPU as [`Hypervisor::enter`] sees it: the tables and tag it runs
/// under, what to do before the entry, and the ISA's own register frame.
///
/// The monitor owns the context for the life of the vCPU and never reads
/// `frame`; the ISA owns `frame` and never reads the rest after the entry
/// except `mmio_value`, which it writes.
#[derive(Clone, Copy, Debug)]
pub struct GuestCtx {
    pub s2: Stage2Root,
    pub vmid: u16,
    pub vcpu: u8,
    /// Where the vCPU starts: read on the first entry only (`started` is
    /// false until then).
    pub entry_pc: u64,
    /// The first argument register of the first entry (the device tree
    /// address or boot argument of the guest's boot protocol).
    pub entry_arg: u64,
    pub started: bool,
    /// Virtual interrupt lines (bit `n`, line `n`) raised since the last
    /// entry: the ISA presents them to the guest's interrupt controller.
    pub irqs: u64,
    /// Host timebase ticks the guest's clock must not count from this entry
    /// on: the time the VM spent held that this vCPU's clock has not yet
    /// taken off. The ISA takes them off the guest's clock (riscv64
    /// `htimedelta`, aarch64 `CNTVOFF_EL2`, x86_64 the VMCB's TSC offset) at
    /// the entry, and the monitor clears them after it: the guest reads a
    /// clock that did not move while the VM was held. A vCPU's first entry
    /// carries all the time the VM has lost, whatever the clock the ISA
    /// started it at: every vCPU of a VM reads one clock.
    pub time_skip: u64,
    /// The emulated access whose answer the guest has not yet seen: the ISA
    /// writes a load's value to the access's register and steps the guest PC
    /// past the instruction before it enters; a store only steps it.
    pub completed: Option<MmioDone>,
    /// Out: the value of the source register of the decoded store that
    /// ended the entry with [`Exit::Mmio`], zero-extended to its size.
    pub mmio_value: u64,
    /// The ISA's register frame and control state; zero until the first entry.
    pub frame: [u64; GUEST_FRAME_WORDS],
}

/// Words of ISA-private state in a [`GuestCtx`]: where the ISA keeps its
/// guest register file, or a pointer to its control block (a VMCB, a vCPU's
/// system-register save area). 56 words is riscv64's whole vCPU state (the
/// 40-word `GuestFrame`, the 12 saved `vs*` CSRs and the hart it last ran
/// on); an ISA whose state is larger keeps it elsewhere and holds the
/// reference here.
pub const GUEST_FRAME_WORDS: usize = 56;

impl GuestCtx {
    /// A vCPU that has not run.
    pub const fn new(s2: Stage2Root, vmid: u16, vcpu: u8, entry_pc: u64, entry_arg: u64) -> GuestCtx {
        GuestCtx {
            s2,
            vmid,
            vcpu,
            entry_pc,
            entry_arg,
            started: false,
            irqs: 0,
            time_skip: 0,
            completed: None,
            mmio_value: 0,
            frame: [0; GUEST_FRAME_WORDS],
        }
    }
}

/// What a monitor needs from the CPU's virtualization extension, the same on
/// every ISA: is it usable, the guest-physical tables, the decode of why
/// a guest stopped, and the entry of a vCPU. Implemented by `ext/hv` of each
/// ISA crate (`HvImpl`).
///
/// Entering a guest (the register frame, the control block) is
/// [`enter`](Self::enter): the ISAs' entry primitives exist (`ext/hv/enter.rs`,
/// `hw.rs`), and the guest-boot step (S6) is what wires each of them to it. An
/// ISA that has not says so with [`can_enter`](Self::can_enter), and a vCPU is
/// refused there instead of started.
pub trait Hypervisor: Send + Sync {
    /// Which extension this is.
    fn kind(&self) -> HvKind;

    /// Whether this boot can host a guest, and why not when it cannot.
    fn status(&self) -> HvStatus;

    /// Width of the guest-physical address space the tables here serve.
    fn gpa_bits(&self) -> u8;

    /// An empty stage-2 table.
    fn stage2_create(&self, mem: &mut dyn StageTableMem) -> Result<Stage2Root, StageError>;

    /// Map the 4 KiB page at guest-physical `gpa` to host-physical `hpa`.
    /// Refuses to replace a mapping.
    fn stage2_map(
        &self,
        s2: &Stage2Root,
        mem: &mut dyn StageTableMem,
        gpa: u64,
        hpa: u64,
        perms: StagePerms,
    ) -> Result<(), StageError>;

    /// Remove the 4 KiB mapping at `gpa`; the host-physical address it named.
    /// The caller flushes ([`stage2_flush`](Self::stage2_flush)) before the
    /// frame is reused.
    fn stage2_unmap(&self, s2: &Stage2Root, mem: &mut dyn StageTableMem, gpa: u64) -> Result<u64, StageError>;

    /// A software walk: the host-physical address and permissions `gpa`
    /// resolves to.
    fn stage2_translate(&self, s2: &Stage2Root, mem: &dyn StageTableMem, gpa: u64) -> Option<(u64, StagePerms)>;

    /// Invalidate the guest TLB entries of VM `vmid` on this CPU's translation
    /// regime (a no-op off the target).
    fn stage2_flush(&self, vmid: u16);

    /// Free every table page, the root included.
    fn stage2_destroy(&self, s2: Stage2Root, mem: &mut dyn StageTableMem);

    /// Decode a trap taken while a guest ran.
    fn decode_exit(&self, raw: &RawExit) -> Exit;

    /// Does [`enter`](Self::enter) run a guest on this ISA? `false` until the
    /// ISA's entry primitive is wired (the guest-boot step): the monitor
    /// refuses to start a vCPU rather than start one that cannot run.
    fn can_enter(&self) -> bool {
        false
    }

    /// Run the vCPU of `ctx` on this hart until the guest stops, and say why
    /// (already decoded). The caller runs it on a hart that holds no
    /// deadline reservation, with host interrupts enabled as the ISA's entry
    /// primitive requires; a physical interrupt that arrives while the guest
    /// runs ends the entry with [`Exit::HostInterrupt`]. Default: the ISA has
    /// no entry, so the guest never ran ([`Exit::InvalidState`]).
    fn enter(&self, ctx: &mut GuestCtx) -> Exit {
        let _ = ctx;
        Exit::InvalidState
    }

    /// Serve the [`Exit::Hypercall`] the vCPU of `ctx` just made: decode the
    /// call from the ISA's register frame, do it through `host`, and put the
    /// answer where the guest reads it. Default: this ISA serves none, and the
    /// monitor faults the vCPU.
    fn hypercall(&self, ctx: &mut GuestCtx, host: &mut dyn HypercallHost) -> HypercallOutcome {
        let _ = (ctx, host);
        HypercallOutcome::Unserved
    }

    /// Execute `fence` on this CPU for the vCPU of `ctx`, which is about to
    /// run here, under its address-space tag (`ctx` names the tables and the
    /// VM id). The caller is the thread that runs that vCPU, before it enters:
    /// a [`HypercallHost::fence`] request is carried out here, never on the
    /// CPU of the vCPU that asked. Default: nothing to do.
    fn remote_fence(&self, ctx: &GuestCtx, fence: &RemoteFence) {
        let _ = (ctx, fence);
    }

    /// The word that names the vCPU `vcpu` of the VM whose tables are `s2` as
    /// the holder of this hart's guest interrupt file (never 0), for an ISA
    /// whose guests have such files; the monitor keeps it per vCPU so an
    /// interrupt handler, which takes no lock, can find the thread to wake
    /// (`azos_syscall::vm::wake_file_owner`). Default: no file, 0.
    fn guest_holder_key(&self, s2: &Stage2Root, vcpu: u8) -> u64 {
        let _ = (s2, vcpu);
        0
    }

    /// Message-signalled identities a guest's interrupt file implements on
    /// this machine (`1..=n`); 0: none (the default), and `Vcpu::inject_msi`
    /// is unsupported.
    fn guest_msi_ids(&self) -> u32 {
        0
    }

    /// The virtual interrupt line (`Vcpu::inject` numbering) the entry
    /// presents as message-signalled identity `id`; `None`: no such identity.
    fn guest_msi_line(&self, id: u32) -> Option<u32> {
        let _ = id;
        None
    }
}

/// A fence one vCPU asks of others (RISC-V SBI RFENCE).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteFence {
    /// Make instruction fetch coherent with prior stores (`fence.i`).
    Insn,
    /// Invalidate the guest's address translations: the guest-virtual range
    /// `start .. start + size` (`size == u64::MAX`: the whole address space),
    /// of one address space (`asid`) or of all of them.
    Tlb { start: u64, size: u64, asid: Option<u64> },
}

/// What serving a hypercall asks of the vCPU loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HypercallOutcome {
    /// Not a call this ISA serves (or no host to serve it through): the vCPU
    /// faults, visibly.
    Unserved,
    /// Done and answered: the guest resumes after the call.
    Served,
    /// The guest stopped its own vCPU (SBI HSM `hart_stop`, PSCI `CPU_OFF`).
    StopVcpu,
    /// The guest ended the machine: `kind` 0 shutdown, 1 cold reboot, 2 warm
    /// reboot; `reason` the guest's word (0: none, 1: failure).
    EndGuest { kind: u32, reason: u32 },
}

/// Why starting another vCPU failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VcpuStartError {
    /// The entry address is not inside the guest's memory.
    BadAddress,
    /// That vCPU already runs.
    AlreadyRunning,
    /// No thread could be made (no hart left that may run it).
    Failed,
}

/// What a hypercall needs of the VM it is made in: the other vCPUs, the
/// virtual interrupt lines, the guest's timer and the remote fences.
/// Implemented by the monitor (the kernel's vCPU loop, which holds the VM); an ISA's
/// [`Hypervisor::hypercall`] is written against this and nothing else, so it
/// runs under the host tests against a fake VM.
///
/// A vCPU is named by its index in the VM, which is also the guest's hart id.
pub trait HypercallHost {
    /// vCPUs the VM has (started or not).
    fn vcpus(&self) -> usize;
    /// Does the thread of vCPU `vcpu` run?
    fn vcpu_running(&self, vcpu: usize) -> bool;
    /// Run the stopped vCPU `vcpu` from guest-physical address `pc`, its
    /// first argument register holding `arg`.
    fn start_vcpu(&mut self, vcpu: usize, pc: u64, arg: u64) -> Result<(), VcpuStartError>;
    /// Raise virtual interrupt line `line` of vCPU `vcpu` (`Vcpu::inject`),
    /// waking it if it waits.
    fn raise_irq(&mut self, vcpu: usize, line: u32);
    /// Make `deadline` (guest time ticks, `u64::MAX`: never) the only pending
    /// deadline of vCPU `vcpu`'s timer. While the guest's time is at or past
    /// it the monitor asserts virtual interrupt line `line` on every entry of
    /// the vCPU (a level: arming a later deadline withdraws it).
    fn arm_timer(&mut self, vcpu: usize, deadline: u64, line: u32);
    /// Ask vCPU `vcpu` to carry out `fence` before it next runs guest code
    /// ([`Hypervisor::remote_fence`] on the hart that runs it). This only
    /// asks: the vCPU loop does not resume the asking vCPU's guest until
    /// every fence it asked has been carried out or its target has ended
    /// (`RunHost::fences_outstanding`), which is what a guest that frees a
    /// page after the call relies on.
    fn fence(&mut self, vcpu: usize, fence: RemoteFence);
}

// ──────────────────────────────────────────────────────────────────────────
// Which ISA impl is active
// ──────────────────────────────────────────────────────────────────────────

/// Compile-time identifier of the active ISA impl, surfaced for
/// diagnostic prints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchId {
    Riscv64,
    Aarch64,
    X86_64,
    /// Test stub (host) — used by host-side unit tests of
    /// kernel logic that depend on the arch trait shape.
    Stub,
}

/// Returns a stable short name for the [`ArchId`] (for logging and
/// manifest fields).
pub const fn arch_name(id: ArchId) -> &'static str {
    match id {
        ArchId::Riscv64 => "riscv64",
        ArchId::Aarch64 => "aarch64",
        ArchId::X86_64 => "x86_64",
        ArchId::Stub => "stub",
    }
}

#[cfg(feature = "lat-trace")]
pub mod lat;

pub mod isa;

pub mod spin;
pub use spin::{CasOrder, SpinWait};

pub mod contig;

/// The Accessed-bit walk behind `Mmu::harvest_accessed` (page aging).
pub mod aging;

pub mod tlb_gen;

pub mod entropy;

/// The performance counters (cycles, instructions, one event) behind `Pmu`.
pub mod pmu;
pub use pmu::{Pmu, PmuCaps};

/// Virtual KASLR (Kconfig `KASLR`): policy, slide choice, relocation walk and
/// device-tree seed, the parts every ISA shares.
pub mod kaslr;

// ──────────────────────────────────────────────────────────────────────────
// Arch contract: ArchPlatform (ISA crates) and ArchEntry (kernel boot hooks)
// ──────────────────────────────────────────────────────────────────────────

mod contract;
pub use contract::{ArchEntry, ArchPlatform, FirmwareMemory, LineHooks};
