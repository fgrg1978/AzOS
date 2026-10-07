// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Adapter — implements the cross-ISA [`azos_arch_api`]
//! traits in terms of the existing RISC-V modules in this crate.
//!
//! Pure additive: the legacy `cpu::*`, `csr::*`, `mmu::*`, `sbi::*`
//! free-function APIs stay in place for in-crate callers (the
//! kernel still calls `csr::read_satp()` directly today). This
//! adapter is the entry point for cross-ISA code that needs to
//! call arch through the trait surface — and for the upcoming
//! aarch64 / x86_64 ports, which will implement the same traits
//! over their own backends.
//!
//! See B0.2 commit message for the rationale.

use azos_arch_api::{
    Boot, Cpu, HartStartError, InterruptState, Interrupts, Mmu, MmuError,
    PagePerms, ArchId, Vector,
};

// ──────────────────────────────────────────────────────────────────────────
// Singleton marker type
// ──────────────────────────────────────────────────────────────────────────

/// ZST marker satisfying every arch-api trait family for RISC-V 64.
/// Held as a static so callers can pass `&RISCV64` wherever a
/// `&dyn Cpu` / `&dyn Mmu` / etc. is expected.
pub struct Riscv64;

/// Singleton instance. Use `&arch_impl::RISCV64` to drive the
/// cross-ISA API from in-tree code while the kernel continues to
/// call the legacy free-function modules directly.
pub static RISCV64: Riscv64 = Riscv64;

/// Architectural identifier surfaced through arch-api.
pub const ARCH_ID: ArchId = ArchId::Riscv64;

// ──────────────────────────────────────────────────────────────────────────
// Cpu
// ──────────────────────────────────────────────────────────────────────────

impl Cpu for Riscv64 {
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
        // `rdtime`, the unprivileged read of the `time` CSR. Same instruction
        // `azos_drv_sys::timebase::now` issues — that module's name is
        // historical, it does not touch the CLINT's MMIO for this.
        //
        // Deliberately NOT a call into `azos_drv_*`: `arch` sits below
        // the driver crates, and an `arch -> drivers` edge to reach one
        // instruction would invert the dependency for nothing.
        let t: u64;
        unsafe { core::arch::asm!("rdtime {}", out(reg) t, options(nomem, nostack)) };
        t
    }

    #[inline(always)]
    fn percpu_base(&self) -> usize {
        let b: usize;
        unsafe { core::arch::asm!("mv {}, tp", out(reg) b, options(nomem, nostack, preserves_flags)) };
        b
    }

    #[inline(always)]
    fn set_percpu_base(&self, base: usize) {
        unsafe { core::arch::asm!("mv tp, {}", in(reg) base, options(nomem, nostack, preserves_flags)) };
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Interrupts
// ──────────────────────────────────────────────────────────────────────────

impl Interrupts for Riscv64 {
    #[inline]
    #[cfg_attr(feature = "lat-trace", track_caller)]
    fn disable_all(&self) -> InterruptState {
        let prev = crate::csr::read_sstatus();
        crate::csr::write_sstatus(prev & !crate::csr::SSTATUS_SIE);
        #[cfg(feature = "lat-trace")]
        if prev & crate::csr::SSTATUS_SIE != 0 {
            crate::lat_hook::irq_off(core::panic::Location::caller());
        }
        InterruptState(prev as u64)
    }

    /// Read-modify-write of `SIE` alone.
    ///
    /// **This wrote the whole saved `sstatus` back until 2026-09-21.** On
    /// aarch64 that shape is right — `DAIF` is a pure mask register. On
    /// RISC-V `sstatus` is shared: `SPIE`, `SPP`, `FS`, `SUM`, `MXR` and
    /// `SD` live in the same word, so a blanket write-back reverts anything
    /// that legitimately changed while interrupts were off.
    ///
    /// Unobservable in this tree today, and said plainly rather than
    /// dressed up as a fix with a rate: `crates/core/arch-riscv64/src/csr.rs`
    /// declares only `SSTATUS_SIE`, `SSTATUS_SPIE` and `SSTATUS_SPP`, and
    /// nothing writes the latter two inside a critical section. What makes
    /// it worth correcting now is that this function had **no production
    /// caller at all** until the `csr` call sites migrated onto it — so the
    /// over-broad version was about to acquire ~55 of them.
    ///
    /// The hand-written idiom in `sched::scheduler` and
    /// `sync::IrqSaveGuard::drop` was already the careful one; this brings
    /// the trait in line with the code it replaces, not the other way round.
    #[inline]
    #[cfg_attr(feature = "lat-trace", track_caller)]
    fn restore(&self, prev: InterruptState) {
        let current = crate::csr::read_sstatus();
        let sie = crate::csr::SSTATUS_SIE;
        #[cfg(feature = "lat-trace")]
        if current & sie == 0 && (prev.0 as usize) & sie != 0 {
            crate::lat_hook::irq_on(core::panic::Location::caller());
        }
        crate::csr::write_sstatus((current & !sie) | ((prev.0 as usize) & sie));
    }

    #[inline]
    #[cfg_attr(feature = "lat-trace", track_caller)]
    fn enable_all(&self) {
        #[cfg(feature = "lat-trace")]
        if crate::csr::read_sstatus() & crate::csr::SSTATUS_SIE == 0 {
            crate::lat_hook::irq_on(core::panic::Location::caller());
        }
        // One `csrsi` instead of `csrr`/`or`/`csrw`: the same bit set, and
        // atomic, so no other `sstatus` bit is written back (SYSFLOOR: this
        // runs on every syscall).
        unsafe {
            core::arch::asm!("csrsi sstatus, {0}", const crate::csr::SSTATUS_SIE, options(nostack));
        }
    }

    #[inline]
    fn interrupts_enabled(&self) -> bool {
        crate::csr::read_sstatus() & crate::csr::SSTATUS_SIE != 0
    }

    #[inline]
    fn set_timer_deadline(&self, deadline_ticks: u64) {
        crate::sbi::set_timer(deadline_ticks);
    }

    #[inline]
    fn send_ipi(&self, target_hart: usize) {
        // RISC-V SBI IPI takes a hart-mask + base; for a single
        // target we set bit 0 of the mask at base = target_hart.
        let _ = crate::sbi::send_ipi(1, target_hart);
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Mmu
// ──────────────────────────────────────────────────────────────────────────

// RISC-V allows an ISA impl to ignore `level` for leaf/table
// classification (Sv39: R|W|X on the word decides leaf-ness at any
// level), so most methods below take it only to satisfy the trait
// shape aarch64 genuinely needs it for. `#[inline]` on every one: this
// workspace builds with `lto = false` (see `crates/core/arch/src/lib.rs`),
// so an un-inlined trait call here would be a real cross-crate call on
// every page-table write.
impl Mmu for Riscv64 {
    const PAGE_SIZE: usize = crate::mmu::PAGE_SIZE;

    #[inline]
    fn levels(&self) -> usize { 3 }

    #[inline]
    fn entries_per_table(&self) -> usize { crate::mmu::PT_ENTRIES }

    #[inline]
    fn vpn(&self, va: usize, level: usize) -> usize {
        match level {
            0 => crate::mmu::vpn0(va),
            1 => crate::mmu::vpn1(va),
            _ => crate::mmu::vpn2(va),
        }
    }

    #[inline]
    fn pte_empty(&self) -> u64 {
        crate::mmu::Pte::empty().0
    }

    #[inline]
    fn pte_is_valid(&self, word: u64) -> bool {
        crate::mmu::Pte(word).is_valid()
    }

    #[inline]
    fn pte_is_table(&self, word: u64, _level: usize) -> bool {
        let p = crate::mmu::Pte(word);
        p.is_valid() && !p.is_leaf()
    }

    #[inline]
    fn pte_is_leaf(&self, word: u64, _level: usize) -> bool {
        crate::mmu::Pte(word).is_leaf()
    }

    #[inline]
    fn pte_phys(&self, word: u64) -> usize {
        crate::mmu::Pte(word).phys_addr()
    }

    #[inline]
    fn pte_make_table(&self, pa: usize) -> u64 {
        crate::mmu::Pte::new(pa, crate::mmu::PteFlags::VALID).0
    }

    #[inline]
    fn pte_make_leaf(&self, pa: usize, perms: PagePerms, _level: usize) -> Result<u64, MmuError> {
        if pa & (Self::PAGE_SIZE - 1) != 0 {
            return Err(MmuError::NotAligned);
        }
        Ok(crate::mmu::Pte::new(pa, riscv_leaf_flags(perms)).0)
    }

    #[inline]
    fn pte_perms(&self, word: u64) -> PagePerms {
        let f = crate::mmu::Pte(word).flags();
        PagePerms {
            read:  f.contains(crate::mmu::PteFlags::READ),
            write: f.contains(crate::mmu::PteFlags::WRITE),
            exec:  f.contains(crate::mmu::PteFlags::EXEC),
            user:  f.contains(crate::mmu::PteFlags::USER),
            // Sv39 has no cacheable bit in the PTE (PMAs govern it via
            // PMP/DTB), so a decoded word is reported cacheable — the
            // common case, and the only one `crates/core/mm` ever builds.
            cache: true,
            accessed: f.contains(crate::mmu::PteFlags::ACCESSED),
            dirty:    f.contains(crate::mmu::PteFlags::DIRTY),
        }
    }

    #[inline]
    fn pte_is_cow(&self, word: u64) -> bool {
        crate::mmu::Pte(word).flags().contains(crate::mmu::PteFlags::COW)
    }

    #[inline]
    fn pte_share_cow(&self, word: u64) -> u64 {
        let p = crate::mmu::Pte(word);
        let flags = (p.flags() - crate::mmu::PteFlags::WRITE) | crate::mmu::PteFlags::COW;
        crate::mmu::Pte::new(p.phys_addr(), flags).0
    }

    #[inline]
    fn pte_break_cow(&self, word: u64) -> u64 {
        let p = crate::mmu::Pte(word);
        let flags = (p.flags() - crate::mmu::PteFlags::COW)
            | crate::mmu::PteFlags::WRITE
            | crate::mmu::PteFlags::DIRTY;
        crate::mmu::Pte::new(p.phys_addr(), flags).0
    }

    #[inline]
    fn pte_make_demand(&self, perms: PagePerms) -> u64 {
        // VALID = 0 (never set below), DEMAND set, desired flags stored
        // in-line for `pte_demand_perms` to recover at fault time.
        crate::mmu::PteFlags::DEMAND.bits() | riscv_leaf_flags_no_valid(perms)
    }

    #[inline]
    fn pte_is_demand(&self, word: u64) -> bool {
        word & crate::mmu::PteFlags::DEMAND.bits() != 0
    }

    #[inline]
    fn pte_demand_perms(&self, word: u64) -> PagePerms {
        let f = crate::mmu::PteFlags::from_bits_truncate(
            word & !crate::mmu::PteFlags::DEMAND.bits(),
        );
        PagePerms {
            read:  f.contains(crate::mmu::PteFlags::READ),
            write: f.contains(crate::mmu::PteFlags::WRITE),
            exec:  f.contains(crate::mmu::PteFlags::EXEC),
            user:  f.contains(crate::mmu::PteFlags::USER),
            cache: true,
            accessed: f.contains(crate::mmu::PteFlags::ACCESSED),
            dirty:    f.contains(crate::mmu::PteFlags::DIRTY),
        }
    }

    #[inline]
    fn switch_pt(&self, root_phys: usize, asid: u16) {
        // `write_satp` already emits `sfence.vma zero, zero` (see
        // `csr::write_satp`) — no second fence here. That used to be a
        // second full TLB flush on every address-space switch.
        let satp = crate::mmu::make_satp(root_phys, asid);
        crate::csr::write_satp(satp);
    }

    /// riscv64 has ONE translation register: the kernel's table and a task's
    /// table are both `satp`, so this is `switch_pt` with ASID 0. Kept as a
    /// distinct method only so `crates/core/mm` can say which of the two it means.
    #[inline]
    fn switch_kernel_pt(&self, root_phys: usize) {
        self.switch_pt(root_phys, 0);
    }

    #[inline]
    fn flush_tlb_all(&self) {
        crate::csr::sfence_vma();
    }

    #[inline]
    fn flush_tlb_asid(&self, _asid: u16) {
        // RISC-V SFENCE.VMA with rs2 != 0 selects by ASID, but the
        // existing `csr::sfence_vma()` flushes all. A per-ASID
        // variant is a follow-up; flushing all preserves
        // correctness at the cost of TLB pressure.
        crate::csr::sfence_vma();
    }

    #[inline]
    fn flush_tlb_page(&self, va: usize) {
        crate::csr::sfence_vma_addr(va);
    }

    #[inline]
    fn tlb_shootdown(&self, root_phys: usize, va: usize, len: usize) -> usize {
        crate::tlb::shootdown(root_phys, va, len)
    }

    #[inline]
    fn root_holders(&self, root_phys: usize) -> usize {
        crate::tlb::holders(root_phys)
    }
}

/// Shared flag-building body for [`Riscv64::pte_make_leaf`] and
/// [`Riscv64::pte_make_demand`] (which stores the same bits minus
/// `VALID`). `cache` is ignored: Sv39 has no cacheable bit in the PTE.
#[inline]
fn riscv_leaf_flags_no_valid(perms: PagePerms) -> u64 {
    let mut flags = crate::mmu::PteFlags::empty();
    if perms.read  { flags |= crate::mmu::PteFlags::READ; }
    if perms.write { flags |= crate::mmu::PteFlags::WRITE; }
    if perms.exec  { flags |= crate::mmu::PteFlags::EXEC; }
    if perms.user  { flags |= crate::mmu::PteFlags::USER; }
    if perms.accessed { flags |= crate::mmu::PteFlags::ACCESSED; }
    if perms.dirty     { flags |= crate::mmu::PteFlags::DIRTY; }
    let _ = perms.cache;
    flags.bits()
}

#[inline]
fn riscv_leaf_flags(perms: PagePerms) -> crate::mmu::PteFlags {
    crate::mmu::PteFlags::VALID
        | crate::mmu::PteFlags::from_bits_truncate(riscv_leaf_flags_no_valid(perms))
}

// ──────────────────────────────────────────────────────────────────────────
// Boot
// ──────────────────────────────────────────────────────────────────────────

impl Boot for Riscv64 {
    #[inline]
    fn shutdown(&self) -> ! {
        crate::sbi::shutdown()
    }

    #[inline]
    fn reboot(&self) -> ! {
        crate::sbi::reboot()
    }

    #[inline]
    fn hart_start(
        &self,
        hart_id: usize,
        start_pc: usize,
        opaque: usize,
    ) -> Result<(), HartStartError> {
        // SBI HSM hart_start returns 0 on success; negative on
        // error. RISC-V SBI doesn't surface a clean
        // AlreadyOn/InvalidHartId split, so we collapse all errors
        // into `Other(rc as i32)` so the caller can log the raw
        // SBI return code.
        let rc = crate::sbi::hart_start(hart_id, start_pc, opaque);
        if rc == 0 {
            Ok(())
        } else {
            Err(HartStartError::Other(rc as i32))
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Vector (B0.3)
// ──────────────────────────────────────────────────────────────────────────
//
// The Vector trait is a **build-time** dispatch on RISC-V: the
// `rvv` Cargo feature is set per platform (k1 enables it via the
// SpacemiT K1's RVV 1.0; QEMU rv64,v=true enables it via `rvv`).
// When the feature is off (QEMU default / VF2), we delegate to
// the scalar fallback that already exists in `crate::rvv`.
//
// A *runtime* probe (read `misa` CSR, check bit 'V') would let
// one binary run on both V-capable and V-less harts; that's a
// follow-up. The build-time form is correct today because every
// `--features qemu/vf2/k1/no-ml/no-mmu` config is for a single
// known target hart family.

impl Vector for Riscv64 {
    #[inline]
    fn dot_f32(&self, a: &[f32], b: &[f32]) -> f32 {
        #[cfg(feature = "rvv")]
        {
            crate::rvv::dot_f32_rvv(a, b)
        }
        #[cfg(not(feature = "rvv"))]
        {
            crate::rvv::dot_f32_scalar(a, b)
        }
    }

    #[inline]
    fn is_accelerated(&self) -> bool {
        cfg!(feature = "rvv")
    }
}