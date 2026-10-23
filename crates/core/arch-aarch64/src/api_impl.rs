// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! arch-api trait impls for ARMv8-A.
//!
//! See `crates/core/arch-riscv64/src/api_impl.rs` for the RISC-V reference
//! version (there is no `crates/core/arch/src/api_impl.rs` — `crates/core/arch` is
//! the target_arch facade that re-exports whichever ISA crate is active,
//! not an impl crate itself). Trait shapes match exactly; the only thing
//! that changes is the backing instructions.

// The arch-api + mmu items are only referenced inside the
// `#[cfg(target_arch = "aarch64")]` impl blocks below. Gate the
// imports too so the workspace's riscv64 target doesn't generate
// unused-import warnings.
#[cfg(target_arch = "aarch64")]
use azos_arch_api::{
    Boot, Cpu, HartStartError, InterruptState, Interrupts, Mmu, MmuError,
    PagePerms, Vector,
};

#[cfg(target_arch = "aarch64")]
use crate::mmu::PAGE_SIZE;
#[cfg(target_arch = "aarch64")]
use crate::ext::tlbi_range;
#[cfg(target_arch = "aarch64")]
use azos_arch_api::isa::aarch64 as policy;

/// ZST marker satisfying every arch-api trait family for ARMv8-A.
pub struct Aarch64;

/// Singleton instance — `&AARCH64` plugs into any
/// `&dyn Cpu` / `&dyn Mmu` / etc. slot.
pub static AARCH64: Aarch64 = Aarch64;

// ──────────────────────────────────────────────────────────────────────────
// Deep idle
// ──────────────────────────────────────────────────────────────────────────

#[cfg(target_arch = "aarch64")]
use crate::firmware::{IdleLadder, PowerStateFormat, SuspendState};
#[cfg(target_arch = "aarch64")]
use core::sync::atomic::{AtomicU8, Ordering};

/// Per CPU (indexed by the per-CPU base, the kernel's CPU id): the idle
/// states `cpu_idle(depth)` can enter. Empty until `install_idle_states`.
#[cfg(target_arch = "aarch64")]
static IDLE_LADDERS: [IdleLadder; crate::cpu::CPUS] = [const { IdleLadder::EMPTY }; crate::cpu::CPUS];

/// The firmware's `power_state` format, once asked: 0 not asked, 1 no
/// `CPU_SUSPEND`, 2 original, 3 extended.
#[cfg(target_arch = "aarch64")]
static SUSPEND_FORMAT: AtomicU8 = AtomicU8::new(0);

#[cfg(target_arch = "aarch64")]
impl Aarch64 {
    /// Tell `cpu_idle` what the device tree's `cpu-idle-states` of CPU `cpu`
    /// are (depth 1 is `states[0]`). Returns the mask of depths that will be
    /// entered as themselves, bit `d - 1` for depth `d`; a depth outside it
    /// is entered as the deepest standby state below it, or `wfi`. 0 when the
    /// firmware has no `CPU_SUSPEND` or `cpu` has no slot. Boot time, after
    /// the PSCI conduit is chosen and before the idle governor runs.
    pub fn install_idle_states(&self, cpu: usize, states: &[SuspendState]) -> u8 {
        let Some(ladder) = IDLE_LADDERS.get(cpu) else { return 0 };
        if SUSPEND_FORMAT.load(Ordering::Relaxed) == 0 {
            let f = match crate::firmware::probe_suspend_format() {
                None => 1,
                Some(PowerStateFormat::Original) => 2,
                Some(PowerStateFormat::Extended) => 3,
            };
            SUSPEND_FORMAT.store(f, Ordering::Relaxed);
        }
        match SUSPEND_FORMAT.load(Ordering::Relaxed) {
            2 => ladder.install(states, PowerStateFormat::Original),
            3 => ladder.install(states, PowerStateFormat::Extended),
            _ => 0,
        }
    }

    /// The depths of CPU `cpu` that lose the PE's context (a power-down
    /// `CPU_SUSPEND`), bit `d - 1` for depth `d`; 0 until
    /// `install_idle_states`. The boot hands it to the energy model.
    pub fn idle_powerdown_depths(&self, cpu: usize) -> u8 {
        IDLE_LADDERS.get(cpu).map_or(0, IdleLadder::powerdown_mask)
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Cpu
// ──────────────────────────────────────────────────────────────────────────

#[cfg(target_arch = "aarch64")]
impl Cpu for Aarch64 {
    #[inline]
    fn hart_id(&self) -> usize {
        crate::cpu::hart_id()
    }

    #[inline]
    fn wfi(&self) {
        crate::cpu::wfi();
    }

    #[inline]
    fn cpu_idle(&self, depth: u8) -> u64 {
        // Depth 0, a depth with no enterable state, and a `CPU_SUSPEND` that
        // returns without sleeping are all `wfi`.
        let t0 = self.now_ticks();
        let slept = depth != 0
            && IDLE_LADDERS
                .get(self.percpu_base())
                .is_some_and(|l| l.enter(depth, crate::firmware::cpu_suspend_standby));
        if !slept {
            crate::cpu::wfi();
        }
        azos_arch_api::ticks_to_us(self.now_ticks().wrapping_sub(t0), crate::timer::freq_hz())
    }

    #[inline]
    fn halt(&self) -> ! {
        loop {
            crate::cpu::wfi();
        }
    }

    #[inline]
    fn now_ticks(&self) -> u64 {
        // `CNTVCT_EL0`, the virtual count register — the generic timer's
        // monotonic counter as Linux reads it at EL1 and as ring 3's vDSO
        // reads it, and the same timebase `set_timer_deadline` writes
        // `CNTV_CVAL_EL0` against, so a deadline computed from a reading
        // needs no conversion.
        crate::sysregs::read_cntvct_el0()
    }

    #[inline(always)]
    fn percpu_base(&self) -> usize {
        let b: usize;
        unsafe { core::arch::asm!("mrs {}, TPIDR_EL1", out(reg) b, options(nomem, nostack, preserves_flags)) };
        b
    }

    #[inline(always)]
    fn set_percpu_base(&self, base: usize) {
        unsafe { core::arch::asm!("msr TPIDR_EL1, {}", in(reg) base, options(nomem, nostack, preserves_flags)) };
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Interrupts
// ──────────────────────────────────────────────────────────────────────────

#[cfg(target_arch = "aarch64")]
impl Interrupts for Aarch64 {
    #[inline]
    #[cfg_attr(feature = "lat-trace", track_caller)]
    fn disable_all(&self) -> InterruptState {
        let prev = crate::sysregs::disable_irq_fiq();
        #[cfg(feature = "lat-trace")]
        if prev & crate::sysregs::DAIF_I == 0 {
            crate::lat_hook::irq_off(core::panic::Location::caller());
        }
        InterruptState(prev)
    }

    /// A blanket write-back is correct here, unlike on RISC-V.
    ///
    /// `DAIF` holds nothing but the four masks (D, A, I, F), so restoring
    /// the whole saved word restores exactly the enable state and no other
    /// architectural state — the contract `Interrupts::restore` states.
    /// `sstatus` is not like this, which is why the RISC-V impl has to
    /// read-modify-write `SIE` alone; see its note.
    #[inline]
    #[cfg_attr(feature = "lat-trace", track_caller)]
    fn restore(&self, prev: InterruptState) {
        #[cfg(feature = "lat-trace")]
        if prev.0 & crate::sysregs::DAIF_I == 0
            && crate::sysregs::read_daif() & crate::sysregs::DAIF_I != 0
        {
            crate::lat_hook::irq_on(core::panic::Location::caller());
        }
        crate::sysregs::write_daif(prev.0);
    }

    /// `MSR DAIFClr, #2` — unmask IRQ. FIQ is deliberately left as it is:
    /// nothing in this tree routes an FIQ, and clearing a mask for an
    /// exception with no handler is how a spurious one becomes a reset.
    #[inline]
    #[cfg_attr(feature = "lat-trace", track_caller)]
    fn enable_all(&self) {
        #[cfg(feature = "lat-trace")]
        if crate::sysregs::read_daif() & crate::sysregs::DAIF_I != 0 {
            crate::lat_hook::irq_on(core::panic::Location::caller());
        }
        crate::sysregs::enable_irq();
    }

    /// Set in `DAIF` means MASKED, so "enabled" is the bit being CLEAR —
    /// the opposite polarity to RISC-V's `SSTATUS_SIE`. Getting this
    /// backwards is the classic aarch64 port bug, so it is asserted by the
    /// test in `tests/host/arch-api-tests` rather than left to the reader.
    #[inline]
    fn interrupts_enabled(&self) -> bool {
        crate::sysregs::read_daif() & crate::sysregs::DAIF_I == 0
    }

    #[inline]
    fn set_timer_deadline(&self, deadline_ticks: u64) {
        // Generic-timer ticks are CNTFRQ_EL0 Hz. The kernel
        // already converts its scheduler ticks to the platform
        // timebase, so this is a direct write.
        crate::sysregs::write_cntv_cval_el0(deadline_ticks);
        crate::sysregs::enable_virt_timer();
    }

    #[inline]
    fn send_ipi(&self, target_hart: usize) {
        // M39 (coordinator / U10-5, audit): this used to hand-roll its own
        // `ICC_SGI1R_EL1` encoding — Aff0/Aff1 only, no Aff2/Aff3/RS, and
        // no `dsb ishst` before the write. `gic::send_sgi`/`sgi1r_encode`
        // (`crates/core/arch-aarch64::gic`) is the tested, complete encoder
        // and carries the barrier
        // `send_sgi`'s own doc says is required whenever the SGI's
        // receiver depends on a store the sender made just before sending
        // it — true here: `scheduler.rs`'s cross-CPU wake writes the
        // target's ready-queue entry before calling `send_ipi`.
        //
        // `target_hart` is a LOGICAL cpu index (0..num_cpus); the SGI names
        // the PE by its MPIDR affinity, which `azos_percpu` maps from the
        // DTB's `/cpus` (on QEMU virt's flat `-smp N` the two coincide; on a
        // clustered board they do not). A CPU the map lacks gets no SGI.
        if let Some(affinity) = azos_percpu::hw_id(target_hart) {
            crate::irq::gic::send_sgi(affinity as u32, 0);
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Mmu
// ──────────────────────────────────────────────────────────────────────────

#[cfg(target_arch = "aarch64")]
impl Mmu for Aarch64 {
    const PAGE_SIZE: usize = PAGE_SIZE;

    #[inline]
    fn levels(&self) -> usize { crate::mmu::LEVELS }

    #[inline]
    fn entries_per_table(&self) -> usize { crate::mmu::ENTRIES_PER_TABLE }

    #[inline]
    fn root_entries(&self) -> usize { crate::mmu::GRANULE.root_entries() }

    #[inline]
    fn vpn(&self, va: usize, level: usize) -> usize { crate::mmu::vpn(va, level) }

    #[inline]
    fn pte_empty(&self) -> u64 { crate::mmu::empty() }

    #[inline]
    fn pte_is_valid(&self, word: u64) -> bool { crate::mmu::is_valid(word) }

    #[inline]
    fn pte_is_table(&self, word: u64, level: usize) -> bool { crate::mmu::is_table(word, level) }

    #[inline]
    fn pte_is_leaf(&self, word: u64, level: usize) -> bool { crate::mmu::is_leaf(word, level) }

    #[inline]
    fn pte_phys(&self, word: u64) -> usize { crate::mmu::phys_addr(word) }

    #[inline]
    fn pte_make_table(&self, pa: usize) -> u64 { crate::mmu::make_table(pa) }

    #[inline]
    fn pte_make_leaf(&self, pa: usize, perms: PagePerms, level: usize) -> Result<u64, MmuError> {
        crate::mmu::make_leaf(pa, perms, level)
    }

    #[inline]
    fn pte_perms(&self, word: u64) -> PagePerms { crate::mmu::perms_of(word) }

    #[inline]
    fn pte_is_cow(&self, word: u64) -> bool { crate::mmu::is_cow(word) }

    #[inline]
    fn pte_share_cow(&self, word: u64) -> u64 { crate::mmu::share_cow(word) }

    #[inline]
    fn pte_break_cow(&self, word: u64) -> u64 { crate::mmu::break_cow(word) }

    #[inline]
    fn pte_make_marker(&self, kind: azos_arch_api::PageMarker, payload: u32) -> u64 {
        crate::mmu::make_marker(kind.code(), payload)
    }

    #[inline]
    fn pte_marker(&self, word: u64) -> Option<(azos_arch_api::PageMarker, u32)> {
        let (code, payload) = crate::mmu::marker_of(word)?;
        Some((azos_arch_api::PageMarker::from_code(code)?, payload))
    }

    #[inline]
    fn pte_make_demand(&self, perms: PagePerms) -> u64 {
        // `Mmu::pte_make_demand` is infallible (mm's demand-reservation
        // path never checked for an error before — `map_demand`'s only
        // failure modes are "already mapped" and OOM on the intermediate
        // table, never a bad `perms`). Every `PagePerms` this tree builds
        // is representable (has `read: true`, the one thing `attr_bits`
        // rejects), so this cannot fail today.
        //
        // If a future caller passes a `!read` request, the fallback is `0`
        // — an EMPTY entry, i.e. no reservation at all. (An earlier version
        // of this comment called that "a read-only marker"; it is not.) The
        // page then faults as unmapped instead of being demand-filled: a
        // wrong but visible outcome, not a panic, which under
        // `panic = "abort"` would be a board reset. The honest fix is to
        // make the trait method fallible if such a caller ever appears.
        crate::mmu::make_demand(perms).unwrap_or(0)
    }

    #[inline]
    fn pte_is_demand(&self, word: u64) -> bool { crate::mmu::is_demand(word) }

    #[inline]
    fn pte_demand_perms(&self, word: u64) -> PagePerms { crate::mmu::demand_perms(word) }

    #[inline]
    fn switch_pt(&self, root_phys: usize, asid: u16) {
        crate::sysregs::write_ttbr0_el1(root_phys, asid);
        // ISB so subsequent fetches see the new translation regime.
        unsafe {
            core::arch::asm!("isb", options(nomem, nostack, preserves_flags));
        }
    }

    /// aarch64 splits the address space: the kernel's table goes in
    /// `TTBR1_EL1`, which a user task's `switch_pt` (TTBR0_EL1) cannot
    /// disturb. `EPD1` must be clear for these walks to happen at all —
    /// `mmu::setup` owns that bit and preserves it across TTBR0 switches.
    #[inline]
    fn switch_kernel_pt(&self, root_phys: usize) {
        crate::sysregs::write_ttbr1_el1(root_phys, 0);
        unsafe {
            core::arch::asm!("isb", options(nomem, nostack, preserves_flags));
        }
        crate::sysregs::tlbi_vmalle1is();
        unsafe {
            core::arch::asm!("isb", options(nomem, nostack, preserves_flags));
        }
    }

    #[inline]
    fn flush_tlb_all(&self) {
        crate::sysregs::tlbi_vmalle1is();
    }

    /// No caller today. Beware: user tables are installed with ASID 0
    /// (`ArchPlatform::user_root_word` drops the tag), so a nonzero `asid`
    /// here matches no entry and flushes nothing.
    #[inline]
    fn flush_tlb_asid(&self, asid: u16) {
        crate::sysregs::tlbi_aside1is(asid);
    }

    /// `ID_AA64MMFR0_EL1.ASIDBits` (bits 7:4): 0b0010 is 16 bits, 0b0000 is
    /// 8; 16 only counts when `TCR_EL1.AS` took the 1 `mmu::setup` writes.
    fn asid_bits(&self) -> u32 {
        let wide = (crate::sysregs::read_id_aa64mmfr0_el1() >> 4) & 0xF == 0b0010;
        if wide && crate::mmu::tcr_as(crate::sysregs::read_tcr_el1()) == 1 { 16 } else { 8 }
    }

    /// Break-before-make unless every CPU has FEAT_BBM level 2
    /// (`features::BbmSurvey`): the weakest CPU's answer, cached as each CPU
    /// came up, not this CPU's live register, which on a heterogeneous
    /// system would let a block made here meet a CPU that aborts on it.
    fn block_change_needs_bbm(&self) -> bool {
        crate::cpu::features::system_needs_bbm()
    }

    /// The contiguous hint (Kconfig `A64_CONTIG_HINT`): architectural, no ID
    /// register to probe.
    #[inline]
    fn contig_run_pages(&self) -> usize {
        if azos_arch_api::contig::A64_HINT { crate::mmu::CONT_PAGES } else { 0 }
    }

    #[inline]
    fn pte_make_contig_leaf(&self, run_pa: usize, index: usize, perms: PagePerms) -> Result<u64, MmuError> {
        if !azos_arch_api::contig::A64_HINT {
            return Err(MmuError::UnrepresentablePerms);
        }
        crate::mmu::make_contig_leaf(run_pa, index, perms)
    }

    #[inline]
    fn pte_is_contig(&self, word: u64) -> bool { crate::mmu::is_contig(word) }

    /// Each member names its own frame; a break only drops the hint.
    #[inline]
    fn pte_contig_member(&self, word: u64, _index: usize) -> u64 { crate::mmu::clear_contig(word) }

    #[inline]
    fn flush_tlb_page(&self, va: usize) {
        crate::sysregs::tlbi_vaae1is(va);
    }

    /// `TLBI ... IS` is broadcast to every PE in the inner-shareable domain
    /// and `DSB ISH` waits for all of them, so the shootdown needs no IPI and
    /// no per-address-space hart mask. One `DSB ISH` covers a whole range.
    ///
    /// ASID-scoped (Kconfig `TLB_ASID_SCOPED`): `TLBI ASIDE1IS` / `VAE1IS`
    /// on the space's recorded ASID, leaving every other space's retained
    /// entries (user leaves carry nG), when `tlb_gen::broadcast_scope_asid`
    /// finds a record of this generation and every PE's TLB of this
    /// generation or never used: the broadcast reaches a PE still on an
    /// older generation, which may hold the space under an older ASID.
    /// Otherwise all ASIDs: `VAAE1IS` / `VMALLE1IS`.
    ///
    /// `tlb-local-only` (gate canary) issues the non-broadcast forms instead,
    /// which must leave another PE's entry live.
    fn tlb_shootdown(&self, root_phys: usize, va: usize, len: usize) -> usize {
        unsafe { core::arch::asm!("dsb ishst", options(nostack, preserves_flags)); }
        let asid = if azos_arch_api::tlb_gen::ASID_SCOPED {
            azos_arch_api::tlb_gen::broadcast_scope_asid((root_phys & 0x0000_ffff_ffff_fffe) >> 12)
        } else {
            0
        };
        let tag = (asid as u64) << 48;
        if len == azos_arch_api::TLB_ALL {
            if asid != 0 {
                #[cfg(not(feature = "tlb-local-only"))]
                unsafe { core::arch::asm!("tlbi aside1is, {0}", in(reg) tag, options(nostack, preserves_flags)); }
                #[cfg(feature = "tlb-local-only")]
                unsafe { core::arch::asm!("tlbi aside1, {0}", in(reg) tag, options(nostack, preserves_flags)); }
            } else {
                #[cfg(not(feature = "tlb-local-only"))]
                unsafe { core::arch::asm!("tlbi vmalle1is", options(nostack, preserves_flags)); }
                #[cfg(feature = "tlb-local-only")]
                unsafe { core::arch::asm!("tlbi vmalle1", options(nostack, preserves_flags)); }
            }
        } else {
            let start = va & !(PAGE_SIZE - 1);
            let end = va.saturating_add(len);
            let one_page = |a: usize| {
                let page = (a as u64) >> 12;
                if asid != 0 {
                    let op = tag | page;
                    #[cfg(not(feature = "tlb-local-only"))]
                    unsafe { core::arch::asm!("tlbi vae1is, {0}", in(reg) op, options(nostack, preserves_flags)); }
                    #[cfg(feature = "tlb-local-only")]
                    unsafe { core::arch::asm!("tlbi vae1, {0}", in(reg) op, options(nostack, preserves_flags)); }
                } else {
                    #[cfg(not(feature = "tlb-local-only"))]
                    unsafe { core::arch::asm!("tlbi vaae1is, {0}", in(reg) page, options(nostack, preserves_flags)); }
                    #[cfg(feature = "tlb-local-only")]
                    unsafe { core::arch::asm!("tlbi vaae1, {0}", in(reg) page, options(nostack, preserves_flags)); }
                }
            };
            let pages = (end - start).div_ceil(PAGE_SIZE);
            if tlbi_range::use_range(tlbi_range::range_on(), pages, policy::TLBIRANGE_MIN_PAGES) {
                // FEAT_TLBIRANGE (`A64_TLBIRANGE`): at most five operations
                // for any length. The `sys` forms, so no assembler feature
                // is needed: RVAE1IS = `sys #0, c8, c2, #1`, RVAAE1IS = #3,
                // the non-broadcast RVAE1 / RVAAE1 = `c8, c6` (the canary).
                let mut a = start;
                for step in tlbi_range::Plan::new(pages) {
                    match step {
                        tlbi_range::Step::Page => one_page(a),
                        tlbi_range::Step::Range { scale, num } => {
                            let op = tlbi_range::operand(tag, a, PAGE_SIZE.trailing_zeros(), scale, num);
                            if asid != 0 {
                                #[cfg(not(feature = "tlb-local-only"))]
                                unsafe { core::arch::asm!("sys #0, c8, c2, #1, {0}", in(reg) op, options(nostack, preserves_flags)); }
                                #[cfg(feature = "tlb-local-only")]
                                unsafe { core::arch::asm!("sys #0, c8, c6, #1, {0}", in(reg) op, options(nostack, preserves_flags)); }
                            } else {
                                #[cfg(not(feature = "tlb-local-only"))]
                                unsafe { core::arch::asm!("sys #0, c8, c2, #3, {0}", in(reg) op, options(nostack, preserves_flags)); }
                                #[cfg(feature = "tlb-local-only")]
                                unsafe { core::arch::asm!("sys #0, c8, c6, #3, {0}", in(reg) op, options(nostack, preserves_flags)); }
                            }
                        }
                    }
                    a += step.pages() * PAGE_SIZE;
                }
            } else {
                let mut a = start;
                while a < end {
                    one_page(a);
                    a += PAGE_SIZE;
                }
            }
        }
        unsafe { core::arch::asm!("dsb ish", "isb", options(nostack, preserves_flags)); }
        0
    }

    /// This PE only: `TTBR0_EL1`'s base address against `root_phys` (ASID
    /// bits 63:48 and CnP bit 0 masked off). Every free of a lived table runs
    /// on the PE that just left it (exit, exec), which is exactly the one
    /// this can see.
    fn root_holders(&self, root_phys: usize) -> usize {
        let live = crate::sysregs::read_ttbr0_el1() & 0x0000_ffff_ffff_fffe;
        if root_phys != 0 && live as usize == root_phys {
            // percpu-hint: the bit only names a hart in a refusal (any non-zero mask refuses the teardown); a stale hart changes the number, not the verdict
            1usize << (crate::cpu::hart_id() & (usize::BITS as usize - 1))
        } else {
            0
        }
    }

    #[inline]
    fn pte_accessed_bit(&self) -> u64 { crate::mmu::AF }

    /// The upper-half alias `phys_to_virt` reads page tables through (a host
    /// build has none).
    #[inline]
    fn table_word(&self, pa: usize) -> *const core::sync::atomic::AtomicU64 {
        #[cfg(target_os = "none")]
        { (pa as u64 | crate::mmu::KERNEL_VA_OFFSET) as usize as *const core::sync::atomic::AtomicU64 }
        #[cfg(not(target_os = "none"))]
        { pa as *const core::sync::atomic::AtomicU64 }
    }

    /// FEAT_HAFDBS with `TCR_EL1.HA` set on the boot PE, and so on every
    /// secondary, which copies `TCR_BOOT_VALUE` (Kconfig `A64_HAFDBS`).
    #[inline]
    fn accessed_in_hardware(&self) -> bool {
        crate::mmu::tcr_ha(crate::mmu::setup::TCR_BOOT_VALUE.load(core::sync::atomic::Ordering::Acquire))
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Boot
// ──────────────────────────────────────────────────────────────────────────

#[cfg(target_arch = "aarch64")]
impl Boot for Aarch64 {
    #[inline]
    fn shutdown(&self) -> ! {
        crate::firmware::system_off()
    }

    #[inline]
    fn reboot(&self) -> ! {
        crate::firmware::system_reset()
    }

    #[inline]
    fn hart_start(
        &self,
        hart_id: usize,
        start_pc: usize,
        opaque: usize,
    ) -> Result<(), HartStartError> {
        // `hart_id` is the logical CPU id; PSCI CPU_ON takes the PE's MPIDR
        // affinity, which `azos_percpu` maps from the DTB's `/cpus`.
        let Some(affinity) = azos_percpu::hw_id(hart_id) else {
            return Err(HartStartError::InvalidHartId);
        };
        let rc = crate::firmware::cpu_on(
            crate::cpu::Mpidr::pack_for_psci(
                affinity as u8,
                (affinity >> 8) as u8,
                (affinity >> 16) as u8,
                (affinity >> 24) as u8,
            ),
            start_pc as u64,
            opaque as u64,
        );
        match rc {
            crate::firmware::PSCI_OK => Ok(()),
            crate::firmware::PSCI_ALREADY_ON => Err(HartStartError::AlreadyOn),
            crate::firmware::PSCI_INVALID_PARAMS
            | crate::firmware::PSCI_INVALID_ADDRESS => {
                Err(HartStartError::InvalidHartId)
            }
            crate::firmware::PSCI_DENIED | crate::firmware::PSCI_DISABLED => {
                Err(HartStartError::Denied)
            }
            other => Err(HartStartError::Other(other)),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Vector (B1.vec)
// ──────────────────────────────────────────────────────────────────────────
//
// The scalar loop: the kernel is soft-float (`fp::dot_f32_scalar`).

#[cfg(target_arch = "aarch64")]
impl Vector for Aarch64 {
    #[inline]
    fn dot_f32(&self, a: &[f32], b: &[f32]) -> f32 {
        crate::fp::dot_f32_scalar(a, b)
    }
}
