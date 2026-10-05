// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Minimal ARMv8-A system-register helpers. Only what the
//! Phase 2 arch-api trait implementations need today — full
//! coverage of EL1 sysregs is a follow-up alongside the boot
//! stub and GIC driver.

/// `DAIF` mask bits. Setting these in `DAIF` *masks* (disables)
/// the corresponding interrupt class — counter-intuitive vs
/// x86/RISC-V where the bit usually means "enabled".
#[allow(dead_code)]
pub const DAIF_D: u64 = 1 << 9; // Debug
#[allow(dead_code)]
pub const DAIF_A: u64 = 1 << 8; // SError
pub const DAIF_I: u64 = 1 << 7; // IRQ
pub const DAIF_F: u64 = 1 << 6; // FIQ

/// All interrupt classes masked. Convenience for
/// `Interrupts::disable_all`.
pub const DAIF_MASK_ALL: u64 = DAIF_D | DAIF_A | DAIF_I | DAIF_F;

/// Read `DAIF`. Returns the current mask bits in the low byte
/// (bits [9:6]).
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn read_daif() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, DAIF",
            out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}

/// Write `DAIF`. Only bits [9:6] are architecturally defined.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn write_daif(val: u64) {
    unsafe {
        core::arch::asm!(
            "msr DAIF, {0}",
            in(reg) val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Disable IRQ + FIQ on the calling CPU. Equivalent to `MSR
/// DAIFSet, #0b1100`. We use the wider [`write_daif`] form so
/// callers can use the returned `DAIF` value as a token to
/// restore later.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn disable_irq_fiq() -> u64 {
    let prev = read_daif();
    write_daif(prev | DAIF_I | DAIF_F);
    prev
}

/// Unmask IRQ (clear DAIF.I). Equivalent to `MSR DAIFClr, #2`.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn enable_irq() {
    unsafe {
        core::arch::asm!(
            "msr DAIFClr, #2",
            options(nomem, nostack),
        );
    }
}

/// Install `addr` as the EL1 exception vector base.
///
/// The address MUST be 2 KiB-aligned (Arm ARM §D7); the symbol
/// itself should use `.align 11` in its asm declaration.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn set_vbar_el1(addr: u64) {
    unsafe {
        core::arch::asm!(
            "msr VBAR_EL1, {0}",
            "isb",
            in(reg) addr,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// ── Generic timer (used by `Interrupts::set_timer_deadline`) ──

/// Read `CNTFRQ_EL0` — generic-timer frequency in Hz. Set by
/// firmware at boot (4 MHz on JH7110, 62.5 MHz on QEMU virt
/// cortex-a72 default).
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn read_cntfrq_el0() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, CNTFRQ_EL0",
            out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}

/// Read `CNTVCT_EL0` — the VIRTUAL count register, the kernel's one clock.
/// Tick units are the generic-timer frequency, available in `CNTFRQ_EL0`.
///
/// Virtual, not physical (`CNTPCT_EL0`), for the reason Linux uses it at
/// EL1: `CNTVCT = CNTPCT - CNTVOFF_EL2`, and ring 3's vDSO reads `CNTVCT_EL0`
/// (`libsys::vdso_now_ns`), so a kernel that stamped with the physical count
/// would disagree with its own user space by whatever offset firmware or a
/// hypervisor left in `CNTVOFF_EL2`. Every kernel stamp, every deadline and
/// the timer comparator below are in this one clock.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn read_cntvct_el0() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, CNTVCT_EL0",
            out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}

/// Set `CNTKCTL_EL1.EL0VCTEN` (bit 1) so EL0 can read `CNTVCT_EL0` (the
/// virtual counter) without trapping — the aarch64 analogue of RISC-V's
/// `scounteren.TM`. Without this, `crates/core/libsys::read_time_csr`'s `mrs
/// cntvct_el0` (used by `vdso_now_ns`, ring 3's zero-ecall exact-time
/// path — RFC-0041 §A parity for aarch64) takes an EC=0x18 "trapped
/// system instruction" exception the first time any user task calls it.
/// Per-PE register: must be called on every hart that will run ring 3,
/// not just the primary.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn enable_el0_cntvct() {
    const EL0VCTEN: u64 = 1 << 1;
    unsafe {
        let mut v: u64;
        core::arch::asm!(
            "mrs {0}, CNTKCTL_EL1",
            out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
        v |= EL0VCTEN;
        core::arch::asm!(
            "msr CNTKCTL_EL1, {0}",
            "isb",
            in(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Write `CNTV_CVAL_EL0` — set the next virtual-timer comparator value.
/// The interrupt (PPI 27, [`crate::gic::PPI_VIRT_TIMER`]) fires when
/// `CNTVCT_EL0 >= CNTV_CVAL_EL0` AND the timer is enabled in `CNTV_CTL_EL0`.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn write_cntv_cval_el0(deadline: u64) {
    unsafe {
        core::arch::asm!(
            "msr CNTV_CVAL_EL0, {0}",
            in(reg) deadline,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Enable the virtual timer + unmask its interrupt
/// (`CNTV_CTL_EL0.ENABLE = 1`, `IMASK = 0`).
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn enable_virt_timer() {
    let ctl: u64 = 1; // ENABLE bit, IMASK clear
    unsafe {
        core::arch::asm!(
            "msr CNTV_CTL_EL0, {0}",
            in(reg) ctl,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// ── MMU control (consumed by Mmu::switch_pt / flush_tlb_*) ──

/// Write `TTBR0_EL1`. The low 16 bits are the ASID (when
/// `TCR_EL1.AS = 1`); the high 48 bits are the page-table root
/// physical address.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn write_ttbr0_el1(root_phys: usize, asid: u16) {
    let val = ((asid as u64) << 48) | (root_phys as u64);
    unsafe {
        core::arch::asm!(
            "msr TTBR0_EL1, {0}",
            in(reg) val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Install `root_phys` (ASID 0) in `TTBR0_EL1` and drop every translation
/// this PE cached under the table it replaces — the same sequence
/// `context_switch.S` runs on an address-space change (`msr`, `isb`,
/// `tlbi vmalle1`, `dsb ish`, `isb`), for a caller that must leave a user
/// table outside a context switch: the exit path, before it frees that table
/// (`azos_sched`'s `release_address_space_at_exit`). Local `tlbi`: no
/// other PE can hold the table's entries, since every PE flushes on its own
/// address-space switches and the table is only ever live on one.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn install_ttbr0_flush_local(root_phys: usize) {
    unsafe {
        core::arch::asm!(
            "msr TTBR0_EL1, {0}",
            "isb",
            "tlbi vmalle1",
            "dsb ish",
            "isb",
            in(reg) root_phys as u64,
            options(nostack, preserves_flags),
        );
    }
}

/// Read `TTBR0_EL1` back. U01-1/U01-2 (audit): `install_device_only_ttbr0`
/// (`crates/core/mm::vmm`) writes the device-only root straight to the register
/// via `ARCH.switch_pt` and returns only a page COUNT, not the root's own
/// physical address — and `crates/core/mm` is out of this migration's file
/// ownership, so this readback (same idiom `read_tcr_el1`/`read_ttbr1_el1`
/// already use to recover a value written through a different call) is how
/// `boot_hooks::arch_hardware_init` (this crate's caller) learns what PA to
/// re-publish into `AARCH64_KERNEL_TTBR0`/`SECONDARY_TTBR0_PA` once the
/// low half stops being the full kernel table.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn read_ttbr0_el1() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, TTBR0_EL1",
            out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}

/// Invalidate the entire TLB at EL1 + inner-shareable DSB.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn tlbi_vmalle1is() {
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Invalidate TLB entries tagged with `asid`. Uses
/// `TLBI ASIDE1IS` which takes the ASID in bits [63:48] of the
/// operand register.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn tlbi_aside1is(asid: u16) {
    let op = (asid as u64) << 48;
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi aside1is, {0}",
            "dsb ish",
            "isb",
            in(reg) op,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Invalidate TLB entries translating `va`, all ASIDs, at EL1 +
/// inner-shareable DSB. `TLBI VAAE1IS` takes bits `[43:0]` of the operand
/// as `VA[55:12]` (the page number, not the byte address) — the same
/// per-page shootdown RISC-V's `sfence.vma va, zero` performs after a
/// single-PTE rewrite (COW break, demand materialize, permission widening,
/// unmap).
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn tlbi_vaae1is(va: usize) {
    let op = (va as u64) >> 12;
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi vaae1is, {0}",
            "dsb ish",
            "isb",
            in(reg) op,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Write `MAIR_EL1` (Memory Attribute Indirection Register). Each
/// 8-bit slot defines a memory type referenced by the AttrIndx
/// field of a stage-1 page-table descriptor.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn write_mair_el1(val: u64) {
    unsafe {
        core::arch::asm!(
            "msr MAIR_EL1, {0}",
            in(reg) val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Write `TCR_EL1` (Translation Control Register).
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn write_tcr_el1(val: u64) {
    unsafe {
        core::arch::asm!(
            "msr TCR_EL1, {0}",
            in(reg) val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Read `ID_AA64MMFR0_EL1`. M41 (coordinator / U10-7, audit): `TCR_EL1.IPS`
/// (the physical-address-range field this crate's `mmu_setup::TCR_VALUE`
/// left at `0` — 32-bit PAs only, so RAM above 4 GiB could never be
/// mapped) must be programmed from THIS register's `PARange` field
/// (bits `[3:0]`), never a value larger than what it reports — the ARM ARM
/// calls a bigger `IPS` write CONSTRAINED UNPREDICTABLE. Guarded by
/// `target_os = "none"` too, same reason `features::detect` is: the host
/// Mac this crate is also compiled on is `target_arch = "aarch64"` but
/// EL0, and `ID_AA64MMFR0_EL1` is EL1-only.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[inline]
pub fn read_id_aa64mmfr0_el1() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, ID_AA64MMFR0_EL1",
            out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}

/// Host-build stub — never executed (nothing calls this off bare-metal
/// aarch64), kept so callers outside a `target_os = "none"` gate still
/// link. See [`read_id_aa64mmfr0_el1`]'s own doc for why the real body is
/// gated this way rather than on `target_arch` alone.
#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
#[inline]
pub fn read_id_aa64mmfr0_el1() -> u64 { 0 }

/// Read `TCR_EL1`. Used by the TTBR1 boot marker (aarch64 parity program,
/// "TTBR1 split") to read back T0SZ/T1SZ from hardware rather than trust
/// the constant that programmed them — a marker that only replays the
/// value it wrote could not tell a real config from a build that skipped
/// the write entirely.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn read_tcr_el1() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, TCR_EL1",
            out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}

/// Write `TTBR1_EL1` — the upper-half (kernel) translation table base
/// register. Same field layout as [`write_ttbr0_el1`] (ASID in bits
/// [63:48], root physical address below).
///
/// Part of the aarch64 parity program's TTBR1 migration. Three callers as
/// of this doc's own check (`grep -rn 'write_ttbr1_el1\|msr TTBR1_EL1'
/// crates kernel --include='*.rs' --include='*.S'`): `mmu_setup::
/// enable_ttbr1_alias` installs the early-boot alias that mirrors the
/// kernel image and RAM at `crate::mmu::KERNEL_VA_OFFSET` — a boot-time
/// proof that TCR_EL1's T1SZ/TG1/IRGN1/ORGN1/SH1 fields and this register
/// are wired correctly; `api_impl::Aarch64::switch_kernel_pt`
/// (`Mmu::switch_kernel_pt`) then replaces that alias with the REAL kernel
/// page table once `crates/core/mm::vmm::init` has built it
/// (`azos_mm::vmm::enable_paging`'s call, `kernel_main`); and
/// `kernel::entry::aarch64::boot.S`'s `_aarch64_secondary_entry` writes it
/// a third way (`msr TTBR1_EL1, {0}` directly, not through this function)
/// to attach each secondary to whichever of the two tables the primary has
/// most recently published — see `kernel::entry::aarch64::
/// aarch64_secondary_ttbr1_attach` and `SECONDARY_TTBR1_PA`'s own doc
/// (U01-1, audit) for why a secondary needed a THIRD publish point rather
/// than reusing the boot-alias one. The kernel DOES execute through this
/// mapping from `enable_paging` onward — every kernel-mode fetch/access at
/// a high VA on every PE resolves through whatever this register (or its
/// per-PE bank) currently holds.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn write_ttbr1_el1(root_phys: usize, asid: u16) {
    let val = ((asid as u64) << 48) | (root_phys as u64);
    unsafe {
        core::arch::asm!(
            "msr TTBR1_EL1, {0}",
            in(reg) val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Read `TTBR1_EL1` back. The boot marker's readback of "what did the
/// hardware actually latch" — see [`write_ttbr1_el1`].
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn read_ttbr1_el1() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, TTBR1_EL1",
            out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}

/// Read `SCTLR_EL1`.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn read_sctlr_el1() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, SCTLR_EL1",
            out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}

/// Write `SCTLR_EL1`. Caller is responsible for an `isb` after if
/// the change must take effect before the next instruction.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn write_sctlr_el1(val: u64) {
    unsafe {
        core::arch::asm!(
            "msr SCTLR_EL1, {0}",
            "isb",
            in(reg) val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// `SCTLR_EL1.M` (bit 0) — global MMU enable for EL1&0 stage 1.
pub const SCTLR_EL1_M: u64 = 1 << 0;
/// `SCTLR_EL1.C` (bit 2) — global data-cache enable.
pub const SCTLR_EL1_C: u64 = 1 << 2;
/// `SCTLR_EL1.I` (bit 12) — global instruction-cache enable.
pub const SCTLR_EL1_I: u64 = 1 << 12;
/// `SCTLR_EL1.SPAN` (bit 23) — "Set PAN": when 1 (this crate's boot value
/// until O3.2), `PSTATE.PAN` is NOT changed on an exception to EL1, so it
/// keeps whatever it was (its architectural reset value, effectively
/// permanently 0 unless software sets it — which nothing here did). Clear
/// (0) so every EL0->EL1 exception SETS `PAN`, matching riscv64's `sstatus.
/// SUM` starting clear (U07-7): EL1 cannot read/write an EL0-taggeed page
/// by accident, only inside an explicit [`UserAccess`] window.
pub const SCTLR_EL1_SPAN: u64 = 1 << 23;

/// O3.2 (owner decision, PAN): RAII guard that clears `PSTATE.PAN` for its
/// lifetime, restoring it on drop. Construct this immediately before the
/// ONE instruction that dereferences a validated user-space physical-page
/// alias or (if ever added) a direct EL0 VA; anything outside its lifetime
/// that touches EL0-taggeed memory faults instead of silently succeeding —
/// that fault IS the protection PAN exists for.
///
/// `MSR PAN, #0/#1` is the immediate form (FEAT_PAN, mandatory under the
/// ARMv8.5-A baseline owner decision 97 targets) — no register round trip,
/// no read-modify-write, unlike `DAIF`.
pub struct UserAccess;

#[cfg(target_arch = "aarch64")]
impl UserAccess {
    #[inline(always)]
    pub fn enable() -> Self {
        unsafe {
            core::arch::asm!(
                ".arch_extension pan",
                "msr PAN, #0",
                options(nomem, nostack, preserves_flags),
            );
        }
        UserAccess
    }
}

#[cfg(not(target_arch = "aarch64"))]
impl UserAccess {
    #[inline(always)]
    pub fn enable() -> Self { UserAccess }
}

#[cfg(target_arch = "aarch64")]
impl Drop for UserAccess {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe {
            core::arch::asm!(
                ".arch_extension pan",
                "msr PAN, #1",
                options(nomem, nostack, preserves_flags),
            );
        }
    }
}
