// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cross-ISA arch trait surface — AZOS Phase 2 prep (B0).
//!
//! This crate defines **what** the kernel needs from any
//! architecture, not **how** any specific architecture provides
//! it. Per RFC-0002 modular pattern, every ISA ships an impl
//! crate (e.g. `azos_arch_riscv64`, `azos_arch_aarch64`,
//! `azos_arch_x86_64`) that satisfies these traits.
//!
//! # Why a new crate now
//!
//! The existing `azos_arch` (~1.3 kL) is 100% RISC-V: bare
//! `pub fn read_satp()`, `pub const SSTATUS_SIE`, etc. There is no
//! abstraction layer separating "what the kernel asks" from "what
//! RISC-V provides". Phase 2 adds `aarch64` and `x86_64` ports;
//! without this trait surface every consumer would have to grow
//! `cfg(target_arch = "...")` branches.
//!
//! # Scope, updated from the original B0 commit
//!
//! B0 itself shipped trait + value-type API only, zero implementations.
//! That is no longer true: `crates/core/arch-riscv64` and `crates/core/arch-aarch64`
//! both implement this trait surface end-to-end (`Cpu`, `Interrupts`,
//! `Mmu`, `Boot`; `Vector` on riscv64), and `azos_kernel` boots both
//! ISAs against it (see `crates/core/arch/src/lib.rs`'s own module doc for the
//! gate evidence). What is still true from B0: most call sites reach the
//! ISA crate directly through the `azos_arch` facade's re-exported
//! modules (`cpu::`, `mmu::`, ...) rather than through these traits — see
//! `crates/core/arch/src/lib.rs` for the measured count of facade-bypass sites,
//! which this trait surface does not close by existing.
//!
//! # The five trait families
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
/// On RISC-V `hart_id()` reads `mhartid` (via early-boot stash);
/// on aarch64 it reads `MPIDR_EL1`; on x86 it reads the APIC ID.
/// The kernel uses `hart_id()` to index per-CPU statics — the
/// only requirement is that distinct cores return distinct values
/// in `0..max_active_harts`.
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
    fn hart_id(&self) -> usize;

    /// Wait For Interrupt — low-power idle. Returns when any
    /// pending interrupt is delivered to this hart.
    fn wfi(&self);

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
/// **`accessed`/`dirty` are request flags, not hardware facts.** Both
/// ISAs support software-managed A/D (no `ADUE`/`HAFDBS` assumed), so a
/// fresh leaf's A/D state is whatever the *caller* asks for via
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

    /// Decode a leaf word's permissions. Level-independent: the
    /// attribute bits (R/W/X/U/cache/A/D) live in the same positions
    /// regardless of which level the leaf was found at.
    fn pte_perms(&self, word: u64) -> PagePerms;

    /// Is the software COW marker set on this word?
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

    /// Switch the current address space to `root_phys` (page
    /// table root physical address). The ASID slot is provided
    /// separately so the impl can re-use it for TLB tagging.
    fn switch_pt(&self, root_phys: usize, asid: u16);

    /// Activate the KERNEL's own page table.
    ///
    /// Separate from [`switch_pt`] because the two are the same register on
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
    /// be running on; nothing publishes the other PEs' roots.
    fn root_holders(&self, root_phys: usize) -> usize;
}

/// `len` for [`Mmu::tlb_shootdown`] meaning "the whole address space".
pub const TLB_ALL: usize = usize::MAX;

/// Page permissions in the cross-ISA model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PagePerms {
    pub read:  bool,
    pub write: bool,
    pub exec:  bool,
    /// Userspace may access. False = kernel-only.
    pub user:  bool,
    /// May be cached. False = device / strongly-ordered.
    pub cache: bool,
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
        read: true, write: true, exec: false, user: false, cache: true,
        accessed: true, dirty: true,
    };
    /// Kernel code; R+X. A preset, no D (never written).
    pub const KERNEL_RX: Self = Self {
        read: true, write: false, exec: true, user: false, cache: true,
        accessed: true, dirty: false,
    };
    /// Kernel R/O data (e.g. `.rodata`). A preset, no D.
    pub const KERNEL_RO: Self = Self {
        read: true, write: false, exec: false, user: false, cache: true,
        accessed: true, dirty: false,
    };
    /// Kernel R/W/X — the coarse identity-map permission `vmm::init` uses
    /// before W^X is enforced section-by-section. A+D preset.
    pub const KERNEL_RWX: Self = Self {
        read: true, write: true, exec: true, user: false, cache: true,
        accessed: true, dirty: true,
    };
    /// User R/W data; no exec. Perm bits only — callers that need A/D
    /// preset (every leaf-creating call site in this tree does) set
    /// `accessed`/`dirty` explicitly, e.g.
    /// `PagePerms { accessed: true, dirty: true, ..PagePerms::USER_RW }`.
    pub const USER_RW: Self = Self {
        read: true, write: true, exec: false, user: true, cache: true,
        accessed: false, dirty: false,
    };
    /// User code; R+X.
    pub const USER_RX: Self = Self {
        read: true, write: false, exec: true, user: true, cache: true,
        accessed: false, dirty: false,
    };
    /// User R/O data.
    pub const USER_RO: Self = Self {
        read: true, write: false, exec: false, user: true, cache: true,
        accessed: false, dirty: false,
    };
    /// A device window mapped into a USER driver (`SYS_MMIO_MAP`): R/W,
    /// uncached, never exec, A+D preset. `mmio_map_user` used `USER_RW`,
    /// which is `cache: true` — on aarch64 that is MAIR Normal write-back,
    /// so device registers could be speculatively read, merged and cached.
    /// riscv64 ignores the bit (PMAs decide), which is why nothing failed.
    pub const USER_MMIO_RW: Self = Self {
        read: true, write: true, exec: false, user: true, cache: false,
        accessed: true, dirty: true,
    };
    /// Read-only user device window. Same reasoning as [`Self::USER_MMIO_RW`].
    pub const USER_MMIO_RO: Self = Self {
        read: true, write: false, exec: false, user: true, cache: false,
        accessed: true, dirty: true,
    };
    /// MMIO region; uncached.
    pub const MMIO: Self = Self {
        read: true, write: true, exec: false, user: false, cache: false,
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
// Where the impls will live (Phase 2 follow-ups)
// ──────────────────────────────────────────────────────────────────────────

/// Compile-time identifier of the active ISA impl, surfaced for
/// `procfs` and diagnostic prints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchId {
    Riscv64,
    Aarch64,
    X86_64,
    /// Test stub (host) — used by host-side unit tests of
    /// kernel logic that depend on the arch trait shape.
    Stub,
}

/// Returns a stable short name for the [`ArchId`] (for logging,
/// procfs, manifest fields).
pub const fn arch_name(id: ArchId) -> &'static str {
    match id {
        ArchId::Riscv64 => "riscv64",
        ArchId::Aarch64 => "aarch64",
        ArchId::X86_64 => "x86_64",
        ArchId::Stub => "stub",
    }
}

/// Masked-window tracer (Kconfig `LAT_TRACE`, cargo feature `lat-trace`).
/// The ISA crates own the hooks; this is the ISA-neutral bookkeeping.
#[cfg(feature = "lat-trace")]
pub mod lat;

// ──────────────────────────────────────────────────────────────────────────
// Arch contract: ArchPlatform (ISA crates) and ArchEntry (kernel boot hooks)
// ──────────────────────────────────────────────────────────────────────────

mod contract;
pub use contract::{ArchEntry, ArchPlatform};
