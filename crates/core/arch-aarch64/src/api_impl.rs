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

/// ZST marker satisfying every arch-api trait family for ARMv8-A.
pub struct Aarch64;

/// Singleton instance — `&AARCH64` plugs into any
/// `&dyn Cpu` / `&dyn Mmu` / etc. slot.
pub static AARCH64: Aarch64 = Aarch64;

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
        // (`tests/qemu/aarch64-smoke` exercises it) and carries the barrier
        // `send_sgi`'s own doc says is required whenever the SGI's
        // receiver depends on a store the sender made just before sending
        // it — true here: `scheduler.rs`'s cross-CPU wake writes the
        // target's ready-queue entry before calling `send_ipi`. One
        // encoder now, not two disagreeing ones for the same register.
        //
        // `target_hart` here is a LOGICAL cpu index (0..num_cpus), not a
        // raw MPIDR affinity — same limitation the old inline encoder had
        // (it packed `target_hart` into aff0/aff1 directly too): on QEMU
        // virt's flat `-smp N` topology the logical index and Aff0 are the
        // same number (Aff1/Aff2/Aff3 are 0), so this is correct there:
        // unlike the old code, if a clustered topology is added the caller
        // still owes this function a real logical->MPIDR lookup — this fix
        // is scoped to "one correct encoder", not "one correct topology
        // mapping" (a separate, larger change touching how the kernel
        // records each hart's MPIDR against its logical id).
        let aff0 = (target_hart & 0xFF) as u8;
        let aff1 = ((target_hart >> 8) & 0xFF) as u8;
        let affinity = crate::mpidr::affinity_key(aff0, aff1, 0, 0);
        crate::gic::send_sgi(affinity, 0);
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
    /// `mmu_setup` owns that bit and preserves it across TTBR0 switches.
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

    #[inline]
    fn flush_tlb_asid(&self, asid: u16) {
        crate::sysregs::tlbi_aside1is(asid);
    }

    #[inline]
    fn flush_tlb_page(&self, va: usize) {
        crate::sysregs::tlbi_vaae1is(va);
    }

    /// `TLBI VAAE1IS` / `VMALLE1IS` are broadcast to every PE in the
    /// inner-shareable domain and `DSB ISH` waits for all of them, so the
    /// shootdown needs no IPI and no per-address-space hart mask. All ASIDs:
    /// this kernel does not tag user translations (`context_switch.S` flushes
    /// with `tlbi vmalle1` on every TTBR0 change). One `DSB ISH` covers a
    /// whole range. `root_phys` is unused for the same reason.
    ///
    /// `tlb-local-only` (gate canary) issues the non-broadcast forms instead,
    /// which must leave another PE's entry live.
    fn tlb_shootdown(&self, _root_phys: usize, va: usize, len: usize) -> usize {
        unsafe { core::arch::asm!("dsb ishst", options(nostack, preserves_flags)); }
        if len == azos_arch_api::TLB_ALL {
            #[cfg(not(feature = "tlb-local-only"))]
            unsafe { core::arch::asm!("tlbi vmalle1is", options(nostack, preserves_flags)); }
            #[cfg(feature = "tlb-local-only")]
            unsafe { core::arch::asm!("tlbi vmalle1", options(nostack, preserves_flags)); }
        } else {
            let mut a = va & !(PAGE_SIZE - 1);
            let end = va.saturating_add(len);
            while a < end {
                let op = (a as u64) >> 12;
                #[cfg(not(feature = "tlb-local-only"))]
                unsafe { core::arch::asm!("tlbi vaae1is, {0}", in(reg) op, options(nostack, preserves_flags)); }
                #[cfg(feature = "tlb-local-only")]
                unsafe { core::arch::asm!("tlbi vaae1, {0}", in(reg) op, options(nostack, preserves_flags)); }
                a += PAGE_SIZE;
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
            1usize << (crate::cpu::hart_id() & (usize::BITS as usize - 1))
        } else {
            0
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Boot
// ──────────────────────────────────────────────────────────────────────────

#[cfg(target_arch = "aarch64")]
impl Boot for Aarch64 {
    #[inline]
    fn shutdown(&self) -> ! {
        crate::psci::system_off()
    }

    #[inline]
    fn reboot(&self) -> ! {
        crate::psci::system_reset()
    }

    #[inline]
    fn hart_start(
        &self,
        hart_id: usize,
        start_pc: usize,
        opaque: usize,
    ) -> Result<(), HartStartError> {
        // PSCI CPU_ON takes MPIDR affinity directly — the caller
        // passes the logical hart_id and we trust it matches the
        // platform's MPIDR layout (kernel boot code builds the
        // mapping when parsing the device tree).
        let rc = crate::psci::cpu_on(
            hart_id as u64,
            start_pc as u64,
            opaque as u64,
        );
        match rc {
            crate::psci::PSCI_OK => Ok(()),
            crate::psci::PSCI_ALREADY_ON => Err(HartStartError::AlreadyOn),
            crate::psci::PSCI_INVALID_PARAMS
            | crate::psci::PSCI_INVALID_ADDRESS => {
                Err(HartStartError::InvalidHartId)
            }
            crate::psci::PSCI_DENIED | crate::psci::PSCI_DISABLED => {
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
// NEON is mandatory on ARMv8 — no probe, no fallback path
// selection. `is_accelerated` returns `true` unconditionally
// because we *always* go through NEON intrinsics.

#[cfg(target_arch = "aarch64")]
impl Vector for Aarch64 {
    #[inline]
    fn dot_f32(&self, a: &[f32], b: &[f32]) -> f32 {
        // Runtime dispatcher — SVE detection lives in vector.rs;
        // path falls back to NEON unconditionally until we have
        // SVE-capable hardware to validate a real `dot_f32_sve`.
        // Same shape as x86_64's AVX/SSE2 dispatch.
        crate::vector::dot_f32_best(a, b)
    }

    #[inline]
    fn is_accelerated(&self) -> bool {
        true
    }
}
