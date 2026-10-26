// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Minimal ARMv8-A system-register helpers. Only what the
//! Phase 2 arch-api trait implementations need today — full
//! coverage of EL1 sysregs is a follow-up alongside the boot
//! stub and GIC driver.

/// `DAIF` mask bits. Setting these in `DAIF` *masks* (disables)
/// the corresponding interrupt class — counter-intuitive vs
/// x86/RISC-V where the bit usually means "enabled".
pub const DAIF_D: u64 = 1 << 9; // Debug
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
    // Not `nomem` (wave 15): every DAIF access is a compiler barrier, so no
    // memory access moves across a mask change. `irq-nomem-canary` puts
    // `nomem` back for the gate's `irq order` canary rows.
    #[cfg(not(feature = "irq-nomem-canary"))]
    unsafe {
        core::arch::asm!("mrs {0}, DAIF", out(reg) v, options(nostack, preserves_flags));
    }
    #[cfg(feature = "irq-nomem-canary")]
    unsafe {
        core::arch::asm!("mrs {0}, DAIF", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// Write `DAIF`. Only bits [9:6] are architecturally defined.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn write_daif(val: u64) {
    // A compiler barrier (no `nomem`): with `nomem`, LLVM could move plain
    // loads and stores across the mask change, out of the window the caller
    // masked interrupts for (found by wave 15 SLAB; `kheap.rs` had to fence).
    #[cfg(not(feature = "irq-nomem-canary"))]
    unsafe {
        core::arch::asm!("msr DAIF, {0}", in(reg) val, options(nostack, preserves_flags));
    }
    #[cfg(feature = "irq-nomem-canary")]
    unsafe {
        core::arch::asm!("msr DAIF, {0}", in(reg) val, options(nomem, nostack, preserves_flags));
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
        // A compiler barrier like `write_daif`: nothing the masked window
        // wrote may sink below the unmask.
        core::arch::asm!(
            "msr DAIFClr, #2",
            options(nostack),
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

/// `CNTKCTL_EL1.EL0PCTEN`: EL0 reads the physical counter.
pub const CNTKCTL_EL0PCTEN: u64 = 1 << 0;
/// `CNTKCTL_EL1.EL0VCTEN`: EL0 reads the virtual counter.
pub const CNTKCTL_EL0VCTEN: u64 = 1 << 1;
/// `CNTKCTL_EL1.EL0VTEN`: EL0 reads and writes the virtual timer.
pub const CNTKCTL_EL0VTEN: u64 = 1 << 8;
/// `CNTKCTL_EL1.EL0PTEN`: EL0 reads and writes the physical timer.
pub const CNTKCTL_EL0PTEN: u64 = 1 << 9;

/// The `CNTKCTL_EL1` this kernel runs with, from the value `v` the PE holds:
/// of the generic timer, EL0 reads the virtual counter and nothing else.
/// The four EL0 bits reset to UNKNOWN, and with `EL0VTEN` set ring 3 could
/// rewrite `CNTV_CTL_EL0` / `CNTV_CVAL_EL0`, the kernel's own tick (Linux's
/// `arch_counter_set_user_access` clears the same bits). The event-stream
/// fields (bits 7:2) are left as they are.
pub const fn cntkctl_el0_access(v: u64) -> u64 {
    if cfg!(feature = "el0-state-canary") {
        // Gate canary: the old read-OR-write, which kept the reset value.
        return v | CNTKCTL_EL0VCTEN;
    }
    (v & !(CNTKCTL_EL0PCTEN | CNTKCTL_EL0VTEN | CNTKCTL_EL0PTEN)) | CNTKCTL_EL0VCTEN
}

/// This PE's EL0-visible state that belongs to no task, set before ring 3
/// first runs here. Per PE: the boot CPU calls it before its tick is armed
/// (`boot_hooks`), each secondary from `secondary_irq_init`. Every value below
/// resets to UNKNOWN on silicon (QEMU resets them to 0):
/// - `CNTKCTL_EL1` ([`cntkctl_el0_access`]): `CNTVCT_EL0` reads without a
///   trap — `crates/core/libsys::read_time_csr`'s `mrs cntvct_el0`
///   (`vdso_now_ns`, ring 3's zero-call clock, the aarch64 counterpart of the
///   riscv64 `rdtime` path) took EC=0x18 without it — and no other EL0 timer
///   access.
/// - `TPIDRRO_EL0` = 0: EL0 reads it, nothing in this kernel writes it
///   (no task has a value), so it held whatever firmware left.
///   (`TPIDR_EL0` is per task, `azos_sched::fp::switch_thread_pointer`.)
/// - `MDSCR_EL1` = [`MDSCR_EL1_BOOT`]: TDCC traps EL0's access to the debug
///   communications channel (`MDCCSR_EL0`, `DBGDTR*_EL0`), a register pair
///   no task owns; single step and the debug exceptions off (Linux's
///   `__cpu_setup` writes the same word). QEMU resets it to 0, EL0 open.
/// - `AMUSERENR_EL0` = 0 where FEAT_AMUv1 is ([`amu_present`]; the register
///   is UNDEFINED without it): EL0 does not read or write the activity
///   monitors (Linux's `reset_amuserenr_el0`). The write needs
///   `CPTR_EL2.TAM` clear, which `_azos_drop_to_el1` leaves; entered at EL1,
///   the boot protocol's EL2 does (as for Linux).
///
/// Gate canary `el0-state-canary`: the reset values are kept, and a non-zero
/// `TPIDRRO_EL0` and the EL0 timer bits stand for firmware's; `MDSCR_EL1`
/// keeps its reset value (ktest `user_visible_state_is_set_on_every_cpu`
/// is `not ok`, with each register named).
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn init_el0_state() {
    // SAFETY: EL1 writes EL0-access controls, an EL0-read-only register and
    // the debug control word; none touches memory. AMUSERENR_EL0 is written
    // only where ID_AA64PFR0_EL1 reports the AMU.
    unsafe {
        let (mut v, pfr0): (u64, u64);
        core::arch::asm!("mrs {0}, CNTKCTL_EL1", "mrs {1}, ID_AA64PFR0_EL1", out(reg) v, out(reg) pfr0,
            options(nomem, nostack, preserves_flags));
        if cfg!(feature = "el0-state-canary") {
            v |= CNTKCTL_EL0PCTEN | CNTKCTL_EL0VTEN | CNTKCTL_EL0PTEN;
        }
        let ro: u64 = if cfg!(feature = "el0-state-canary") { 0x5a5a_0000_0000_0e10 } else { 0 };
        core::arch::asm!(
            "msr CNTKCTL_EL1, {0}",
            "msr TPIDRRO_EL0, {1}",
            in(reg) cntkctl_el0_access(v),
            in(reg) ro,
            options(nomem, nostack, preserves_flags),
        );
        if !cfg!(feature = "el0-state-canary") {
            core::arch::asm!("msr MDSCR_EL1, {0}", in(reg) MDSCR_EL1_BOOT, options(nomem, nostack, preserves_flags));
        }
        if amu_present(pfr0) {
            // AMUSERENR_EL0 by its encoding (an Armv8.4 name).
            core::arch::asm!("msr S3_3_C13_C2_3, xzr", options(nomem, nostack, preserves_flags));
        }
        core::arch::asm!("isb", options(nomem, nostack, preserves_flags));
    }
}

/// `MDSCR_EL1.SS` (bit 0): software step.
pub const MDSCR_EL1_SS: u64 = 1 << 0;
/// `MDSCR_EL1.TDCC` (bit 12): EL0 access to the debug communications
/// channel traps (to EL1).
pub const MDSCR_EL1_TDCC: u64 = 1 << 12;
/// `MDSCR_EL1.KDE` (bit 13): debug exceptions taken at the EL they target.
pub const MDSCR_EL1_KDE: u64 = 1 << 13;
/// `MDSCR_EL1.MDE` (bit 15): breakpoint and watchpoint debug exceptions.
pub const MDSCR_EL1_MDE: u64 = 1 << 15;
/// The `MDSCR_EL1` every PE runs with ([`init_el0_state`]): the channel
/// closed to EL0, no debug event enabled (nothing in this kernel uses
/// hardware breakpoints or software step).
pub const MDSCR_EL1_BOOT: u64 = MDSCR_EL1_TDCC;

/// FEAT_AMUv1 from `ID_AA64PFR0_EL1` (AMU, bits 47:44, non-zero).
pub const fn amu_present(pfr0: u64) -> bool {
    (pfr0 >> 44) & 0xF != 0
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
/// (`azos_sched`'s `release_address_space_at_exit`). Local `tlbi`: other
/// PEs may still hold the table's entries under its ASID (Kconfig
/// `TLB_RETAIN`), but no PE installs that ASID again before an ASID
/// generation change, which flushes it first (`azos_sched::asid`).
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
/// (the physical-address-range field this crate's `mmu::setup::TCR_VALUE`
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
/// crates kernel --include='*.rs' --include='*.S'`): `mmu::setup::
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
/// `SCTLR_EL1.EnIA` (bit 31) — EL0/EL1 instruction-address key A enabled
/// (FEAT_PAuth); clear, `pacia`/`autia` are no-ops. Gates `HWCAP_A64_PAUTH`.
pub const SCTLR_EL1_ENIA: u64 = 1 << 31;
/// `SCTLR_EL1.ATA0` (bit 42) — EL0 allocation-tag access (FEAT_MTE2);
/// clear, EL0 tag loads read 0 and tag stores are ignored. Gates
/// `HWCAP_A64_MTE`.
pub const SCTLR_EL1_ATA0: u64 = 1 << 42;
/// `SCTLR_EL1.SPAN` (bit 23) — "Set PAN": when 1 (this crate's boot value
/// until O3.2), `PSTATE.PAN` is NOT changed on an exception to EL1, so it
/// keeps whatever it was (its architectural reset value, effectively
/// permanently 0 unless software sets it — which nothing here did). Clear
/// (0) so every EL0->EL1 exception SETS `PAN`, matching riscv64's `sstatus.
/// SUM` starting clear (U07-7): EL1 cannot read/write an EL0-taggeed page
/// by accident, only inside an explicit [`UserAccess`] window.
pub const SCTLR_EL1_SPAN: u64 = 1 << 23;
/// `SCTLR_EL1.UMA` (bit 9): EL0 may read and write `DAIF`.
pub const SCTLR_EL1_UMA: u64 = 1 << 9;
/// `SCTLR_EL1.EnRCTX` (bit 10, FEAT_SPECRES): EL0 may run the
/// prediction-restriction instructions (`cfp`/`dvp`/`cpp RCTX`).
pub const SCTLR_EL1_ENRCTX: u64 = 1 << 10;
/// `SCTLR_EL1.DZE` (bit 14): EL0 may run `DC ZVA` (and `DCZID_EL0.DZP` says so).
pub const SCTLR_EL1_DZE: u64 = 1 << 14;
/// `SCTLR_EL1.UCT` (bit 15): EL0 may read `CTR_EL0`.
pub const SCTLR_EL1_UCT: u64 = 1 << 15;
/// `SCTLR_EL1.nTWI` (bit 16): EL0's `WFI` does not trap.
pub const SCTLR_EL1_NTWI: u64 = 1 << 16;
/// `SCTLR_EL1.nTWE` (bit 18): EL0's `WFE` does not trap.
pub const SCTLR_EL1_NTWE: u64 = 1 << 18;
/// `SCTLR_EL1.TSCXT` (bit 20): EL0's access to `SCXTNUM_EL0` traps
/// (FEAT_CSV2_2 / CSV2_1p2; RES1 on a core without it).
pub const SCTLR_EL1_TSCXT: u64 = 1 << 20;
/// `SCTLR_EL1.E0E` (bit 24): EL0's data accesses are big-endian.
pub const SCTLR_EL1_E0E: u64 = 1 << 24;
/// `SCTLR_EL1.UCI` (bit 26): EL0 may run the cache maintenance
/// instructions (`DC CVAU/CVAC/CVAP/CIVAC`, `IC IVAU`).
pub const SCTLR_EL1_UCI: u64 = 1 << 26;
/// `SCTLR_EL1.EnTP2` (bit 60, FEAT_SME): EL0 may use `TPIDR2_EL0`.
pub const SCTLR_EL1_ENTP2: u64 = 1 << 60;

/// The `SCTLR_EL1` word every PE starts from, on both entry paths (boot.S
/// writes it before any compiled code runs; `_azos_drop_to_el1` before its
/// `eret`): MMU, caches and alignment checks off; little-endian at EL1 and
/// EL0; the stack-alignment checks on; exception entry and return context
/// synchronising; the RES1 bits of Armv8.0 (11, 20, 22, 23, 28, 29) set. Of
/// what EL0 may reach ([`SCTLR_EL1_EL0`]), only `WFI`/`WFE` without a trap:
/// no `DAIF`, `CTR_EL0`, `DC ZVA`, cache maintenance, `SCXTNUM_EL0` or
/// `TPIDR2_EL0`. Nothing in ring 3 uses those (relibc, stdrt and the Linux
/// servers read none; glibc and musl read `DCZID_EL0.DZP` before `DC ZVA`),
/// so they stay closed where Linux opens UCT, DZE and UCI. `SCXTNUM_EL0`
/// is closed because no task's value is switched (Linux sets TSCXT too).
/// SPAN is 1 here; boot.S clears it where PAN is in use
/// ([`sctlr_el1_boot`]). Later writers set named bits only: the MMU and
/// cache enables (`mmu::setup`), the pointer-authentication keys
/// (`cpu::cfi`), DSSBS (`ext::mitigations`).
///
/// Before this, a kernel entered at EL1 directly (QEMU without
/// `virtualization=on`: the gate) ran on the firmware's word, read-OR'd with
/// M, C and I: QEMU's reset leaves SPAN 1, so an exception from EL0 kept the
/// PSTATE.PAN of EL0 (0) and the kernel ran without PAN until its first
/// [`UserAccess`] window closed; and TSCXT 0, so ring 3 read and wrote
/// `SCXTNUM_EL0`, which follows no task.
pub const SCTLR_EL1_BOOT: u64 = 0x30D5_0838;
const _: () = assert!(SCTLR_EL1_BOOT >> 32 == 0, "boot.S builds the word with movz/movk of two halves");
#[cfg(target_os = "none")]
const _: () = assert!(crate::ext::hv::world::SCTLR_EL1_RESET == SCTLR_EL1_BOOT, "a guest starts from the host's word");

/// The `SCTLR_EL1` bits that decide what EL0 may do, and SPAN, which decides
/// the PSTATE.PAN the kernel runs with after an exception from EL0: the
/// ktest `user_visible_state_is_set_on_every_cpu` reads them on every PE.
pub const SCTLR_EL1_EL0: u64 = SCTLR_EL1_UMA | SCTLR_EL1_ENRCTX | SCTLR_EL1_DZE | SCTLR_EL1_UCT
    | SCTLR_EL1_NTWI | SCTLR_EL1_NTWE | SCTLR_EL1_TSCXT | SCTLR_EL1_SPAN | SCTLR_EL1_E0E
    | SCTLR_EL1_UCI | SCTLR_EL1_ENTP2;

/// [`SCTLR_EL1_BOOT`] on a PE where PAN is in use (`pan`): SPAN clear, so
/// every exception to EL1 sets PSTATE.PAN.
pub const fn sctlr_el1_boot(pan: bool) -> u64 {
    if pan { SCTLR_EL1_BOOT & !SCTLR_EL1_SPAN } else { SCTLR_EL1_BOOT }
}

/// `ESR_EL1.EC` of a Data Abort taken without a change in Exception level:
/// an EL1 access faulted.
pub const ESR_EC_DATA_ABORT_CUR: u64 = 0x25;
/// `ESR_EL1.ISS.DFSC` (bits [5:0]) of a Data Abort: Alignment fault.
pub const ESR_DFSC_ALIGNMENT: u64 = 0b10_0001;

/// Is the live syndrome `esr` an EL1 data access that took an Alignment
/// fault? With `SCTLR_EL1.A` clear (boot value, `mmu/boot.rs`) a Normal
/// memory load or store at any address takes none; an exclusive or
/// acquire/release access off its natural alignment does (`ldxr`, `ldar`,
/// an LSE atomic across 16 bytes), and so does any Device memory access.
/// The trap entry sends this fault to I-13's rollback
/// (`azos_safety_core::txn`); every other abort keeps the page-fault path.
pub const fn el1_alignment_fault(esr: u64) -> bool {
    (esr >> 26) & 0x3F == ESR_EC_DATA_ABORT_CUR && esr & 0x3F == ESR_DFSC_ALIGNMENT
}

/// O3.2 (owner decision, PAN): RAII guard that clears `PSTATE.PAN` for its
/// lifetime, restoring it on drop. Construct this immediately before the
/// ONE instruction that dereferences a validated user-space physical-page
/// alias or (if ever added) a direct EL0 VA; anything outside its lifetime
/// that touches EL0-taggeed memory faults instead of silently succeeding —
/// that fault IS the protection PAN exists for.
///
/// `MSR PAN, #0/#1` is the immediate form: no register round trip, no
/// read-modify-write, unlike `DAIF`. It is FEAT_PAN (Armv8.1) and UNDEFINED
/// on an Armv8.0 core, so it runs only as Kconfig `A64_PAN` allows:
/// `require` emits it unconditionally (every level >= 8.1, the Raspberry
/// Pi 5), `probe` only when the boot found the feature ([`pan_init`]),
/// `n` never.
pub struct UserAccess;

/// `A64_PAN=probe` only: the boot's answer (ID_AA64MMFR1_EL1.PAN), stored
/// once by [`pan_init`] on the boot CPU before any task exists. Never read
/// under `require` or `n`: [`pan_in_use`] folds to a constant there.
static PAN_PRESENT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Record whether this CPU implements FEAT_PAN (`IdRegs::pan`). Called once,
/// before the first [`UserAccess`]; boot.S makes the same decision for the
/// initial `PSTATE.PAN` from the same register.
pub fn pan_init(present: bool) {
    PAN_PRESENT.store(present, core::sync::atomic::Ordering::Relaxed);
}

/// Is `PSTATE.PAN` in use on this boot: a constant under `require`/`n`,
/// the boot probe's answer under `probe`.
#[inline(always)]
pub fn pan_in_use() -> bool {
    use azos_arch_api::isa::{aarch64::PAN, ExtPolicy};
    match PAN {
        ExtPolicy::Require => true,
        ExtPolicy::Never => false,
        ExtPolicy::Probe => PAN_PRESENT.load(core::sync::atomic::Ordering::Relaxed),
    }
}

/// `A64_PAN=probe`: the key and kinds of a PAN boot-once site in
/// `.azos_keys` (`azos_trace::jump::{KEY_A64_PAN, KIND_A64_PAN_CLR,
/// KIND_A64_PAN_SET}`; the kernel asserts they agree). This crate sees only
/// `azos_arch_api`, so the numbers are mirrored here.
pub const PAN_SITE_KEY: u32 = 64;
/// See [`PAN_SITE_KEY`]: the window's `msr PAN, #0`.
pub const PAN_SITE_KIND_CLR: u32 = 3;
/// See [`PAN_SITE_KEY`]: the window's closing `msr PAN, #1`.
pub const PAN_SITE_KIND_SET: u32 = 4;

/// `A64_PAN=probe`, one boot-once site: an aligned 32-bit instruction linked
/// as `b` to a slow path that tests [`PAN_PRESENT`] and runs the `msr` when
/// it is set, and recorded in `.azos_keys`. The boot rewrites the site ONCE,
/// on the boot CPU before any secondary starts, to the `msr` itself (the
/// CPU has FEAT_PAN) or to a `nop` (an Armv8.0 core), so after boot the
/// window costs what `require` or `n` costs: no load, no branch. A kernel
/// that cannot patch keeps the branch and stays correct.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
macro_rules! pan_site {
    ($kind:expr, $imm:literal) => {
        // SAFETY: one instruction and a table entry; the slow path is the
        // runtime test, correct whichever word the site holds. No `nomem`:
        // the window's user access must not move across the site.
        unsafe {
            core::arch::asm!(
                "2: b {slow}",
                ".pushsection .azos_keys, \"a\"",
                ".balign 8",
                ".8byte 2b",
                ".8byte {slow}",
                ".4byte {key}",
                ".4byte {kind}",
                ".popsection",
                slow = label {
                    if PAN_PRESENT.load(core::sync::atomic::Ordering::Relaxed) {
                        // SAFETY: FEAT_PAN is present (the boot probe).
                        unsafe {
                            core::arch::asm!(
                                ".arch_extension pan",
                                concat!("msr PAN, #", $imm),
                                options(nostack, preserves_flags),
                            );
                        }
                    }
                },
                key = const PAN_SITE_KEY,
                kind = const $kind,
                options(nostack, preserves_flags),
            );
        }
    };
}

#[cfg(target_arch = "aarch64")]
impl UserAccess {
    #[inline(always)]
    pub fn enable() -> Self {
        use azos_arch_api::isa::{aarch64::PAN, ExtPolicy};
        match PAN {
            ExtPolicy::Require => unsafe {
                core::arch::asm!(
                    ".arch_extension pan",
                    "msr PAN, #0",
                    options(nomem, nostack, preserves_flags),
                );
            },
            ExtPolicy::Never => {}
            #[cfg(target_os = "none")]
            ExtPolicy::Probe => pan_site!(PAN_SITE_KIND_CLR, "0"),
            #[cfg(not(target_os = "none"))]
            ExtPolicy::Probe => {
                if pan_in_use() {
                    unsafe { core::arch::asm!(".arch_extension pan", "msr PAN, #0", options(nomem, nostack, preserves_flags)) };
                }
            }
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
        use azos_arch_api::isa::{aarch64::PAN, ExtPolicy};
        match PAN {
            ExtPolicy::Require => unsafe {
                core::arch::asm!(
                    ".arch_extension pan",
                    "msr PAN, #1",
                    options(nomem, nostack, preserves_flags),
                );
            },
            ExtPolicy::Never => {}
            #[cfg(target_os = "none")]
            ExtPolicy::Probe => pan_site!(PAN_SITE_KIND_SET, "1"),
            #[cfg(not(target_os = "none"))]
            ExtPolicy::Probe => {
                if pan_in_use() {
                    unsafe { core::arch::asm!(".arch_extension pan", "msr PAN, #1", options(nomem, nostack, preserves_flags)) };
                }
            }
        }
    }
}
