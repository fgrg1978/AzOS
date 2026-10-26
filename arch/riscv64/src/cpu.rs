// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Halt the CPU until an interrupt arrives.
#[inline(always)]
pub fn wfi() {
    unsafe {
        core::arch::asm!("wfi");
    }
}

/// This CPU's logical id, from the `tp` register: dense, the boot hart is 0,
/// and not the hardware `mhartid` (`azos_percpu::hw_id` maps one to the other
/// at the SBI, PLIC and IMSIC boundaries).
#[inline(always)]
pub fn hart_id() -> usize {
    let id: usize;
    unsafe {
        core::arch::asm!("mv {}, tp", out(reg) id);
    }
    id
}

/// Read the monotonic tick counter — `rdtime`, the unprivileged read of the
/// `time` CSR.
///
/// The free-function twin of [`crate::api_impl::Riscv64`]'s
/// `Cpu::now_ticks`, in the same shape `hart_id` and `wfi` above have: the
/// kernel reaches these through the `azos_arch` facade without
/// constructing a trait object.
///
/// Units are platform-defined; the kernel needs only monotonicity, and this is
/// deliberately the same timebase `set_timer` programs against, so a deadline
/// computed from a reading needs no conversion.
#[inline(always)]
pub fn now_ticks() -> u64 {
    let t: u64;
    unsafe { core::arch::asm!("rdtime {}", out(reg) t, options(nomem, nostack)) };
    t
}

/// Does a read of the `time` CSR complete without a trap reaching S-mode?
/// Boot hart, once (`install_vdso`): the answer decides whether ring 3 reads
/// the clock itself (vDSO `VDSO_FLAG_RDTIME_NATIVE`).
///
/// U-mode reads `time` when both enables let it: `mcounteren.TM`, which the
/// SBI firmware sets for S- and U-mode (OpenSBI writes it at hart init), and
/// `scounteren.TM`, which this kernel sets on every hart (`trap_init`
/// writes `pmu::SCOUNTEREN_BOOT`, `pmu::start_this_cpu` rewrites it). Where
/// the hart has no `time` CSR, the read traps into M-mode and OpenSBI answers
/// it from `mtime`, so it still never reaches this kernel.
/// What neither serves nor emulates the read reaches S-mode as an illegal
/// instruction, and this probe, under a private `stvec`, sees that.
pub fn time_readable() -> bool {
    // SAFETY: the routine installs its own stvec with interrupts off and
    // restores both; it reads one CSR; no memory.
    unsafe { azos_time_probe() != 0 }
}

// `azos_time_probe() -> a0` (1: `time` read, 0: it trapped). The shape of
// `pmu.rs`'s `azos_pmu_probe`: sstatus.SIE cleared, a private stvec whose
// handler clears a0 and resumes after the read, stvec and SIE restored.
// Clobbers t0-t3.
core::arch::global_asm!(
    ".pushsection .text.azos_time_probe, \"ax\"",
    ".globl azos_time_probe",
    ".p2align 2",
    "azos_time_probe:",
    "    csrrci t3, sstatus, 2",
    "    csrr   t1, stvec",
    "    la     t0, 1f",
    "    csrw   stvec, t0",
    "    li     a0, 1",
    "    csrr   t2, time",
    "    csrw   stvec, t1",
    "    andi   t3, t3, 2",
    "    csrs   sstatus, t3",
    "    ret",
    ".p2align 2",
    "1:  li     a0, 0",
    "    csrr   t0, sepc",
    "    addi   t0, t0, 4",
    "    csrw   sepc, t0",
    "    sret",
    ".popsection",
);

unsafe extern "C" {
    fn azos_time_probe() -> usize;
}

// RISC-V CSR (Control and Status Register) access: every function below is
// an inline-asm read or write of one CSR.

// ============================================================
// S-mode CSR functions
// ============================================================

#[inline(always)]
pub fn read_satp() -> usize {
    let val: usize;
    unsafe { core::arch::asm!("csrr {}, satp", out(reg) val) };
    val
}

/// Install `val` in `satp` and flush this hart's TLB. Publishes `val` as this
/// hart's translation root first, for the shootdown (`crate::tlb`).
#[inline(always)]
pub fn write_satp(val: usize) {
    // percpu-hint: callers run with interrupts off (switch, exec install, boot): the published record and the csrw are one hart
    let hart = hart_id();
    crate::tlb::publish(hart, val);
    // Installed outside `azos_sched::asid::prepare_switch`: the hart's TLB
    // generation is unknown from here on, so its next user switch flushes
    // (Kconfig `TLB_RETAIN`; nothing with it off).
    azos_arch_api::tlb_gen::mark_stale(hart);
    unsafe {
        core::arch::asm!(
            "csrw satp, {}",
            "sfence.vma zero, zero",
            in(reg) val,
            options(nostack)
        );
    }
}

#[inline(always)]
pub fn sfence_vma() {
    unsafe { core::arch::asm!("sfence.vma zero, zero", options(nostack)) };
}

#[inline(always)]
pub fn sfence_vma_addr(vaddr: usize) {
    unsafe { core::arch::asm!("sfence.vma {}, zero", in(reg) vaddr, options(nostack)) };
}

/// Every non-global entry tagged `asid` (`sfence.vma zero, asid`).
#[inline(always)]
pub fn sfence_vma_asid(asid: usize) {
    unsafe { core::arch::asm!("sfence.vma zero, {}", in(reg) asid, options(nostack)) };
}

/// The non-global entry for `vaddr` tagged `asid` (`sfence.vma vaddr, asid`).
#[inline(always)]
pub fn sfence_vma_addr_asid(vaddr: usize, asid: usize) {
    unsafe { core::arch::asm!("sfence.vma {}, {}", in(reg) vaddr, in(reg) asid, options(nostack)) };
}

#[inline(always)]
pub fn read_sstatus() -> usize {
    let val: usize;
    // A compiler barrier on purpose (no `nomem`): `sstatus` holds `SIE`, and
    // no memory access may move across an interrupt-mask change. The
    // `irq-nomem-canary` arm exists only for the gate's `irq order` canary.
    #[cfg(not(feature = "irq-nomem-canary"))]
    unsafe { core::arch::asm!("csrr {}, sstatus", out(reg) val) };
    #[cfg(feature = "irq-nomem-canary")]
    unsafe { core::arch::asm!("csrr {}, sstatus", out(reg) val, options(nomem, nostack)) };
    val
}

#[inline(always)]
pub fn write_sstatus(val: usize) {
    #[cfg(not(feature = "irq-nomem-canary"))]
    unsafe { core::arch::asm!("csrw sstatus, {}", in(reg) val, options(nostack)) };
    #[cfg(feature = "irq-nomem-canary")]
    unsafe { core::arch::asm!("csrw sstatus, {}", in(reg) val, options(nomem, nostack)) };
}

#[inline(always)]
pub fn read_stvec() -> usize {
    let val: usize;
    unsafe { core::arch::asm!("csrr {}, stvec", out(reg) val) };
    val
}

#[inline(always)]
pub fn write_stvec(val: usize) {
    unsafe { core::arch::asm!("csrw stvec, {}", in(reg) val, options(nostack)) };
}

#[inline(always)]
pub fn read_sie() -> usize {
    let val: usize;
    unsafe { core::arch::asm!("csrr {}, sie", out(reg) val) };
    val
}

#[inline(always)]
pub fn write_sie(val: usize) {
    unsafe { core::arch::asm!("csrw sie, {}", in(reg) val, options(nostack)) };
}

#[inline(always)]
pub fn write_sscratch(val: usize) {
    unsafe { core::arch::asm!("csrw sscratch, {}", in(reg) val, options(nostack)) };
}

#[inline(always)]
pub fn write_scounteren(val: usize) {
    unsafe { core::arch::asm!("csrw scounteren, {}", in(reg) val, options(nostack)) };
}

/// Clear S-mode software interrupt pending bit (SIP.SSIP, bit 1).
/// Used after handling an IPI to acknowledge the interrupt.
#[inline(always)]
pub fn clear_sip_ssip() {
    unsafe { core::arch::asm!("csrc sip, {}", in(reg) 1usize << 1, options(nostack)) };
}

// ---- sstatus bit definitions ----

pub const SSTATUS_SIE: usize = 1 << 1;
pub const SSTATUS_SPIE: usize = 1 << 5;
pub const SSTATUS_SPP: usize = 1 << 8;
/// `sstatus.SUM` (bit 18) — Supervisor User Memory access. 0 (this crate's
/// boot value; nothing here ever sets it — U07-7/O3.2, audit) means S-mode
/// faults on ANY access to a `U=1` PTE, full stop; the copy_* routines in
/// `crates/core/sched::process` never hit this today because they translate a
/// user VA to its physical frame and access it through the kernel's own
/// `phys_to_virt` window (a `U=0` mapping) rather than the user's own VA —
/// so SUM has been architecturally irrelevant to them. It matters for the
/// bug PAN targets on aarch64: a DIFFERENT piece of kernel code that
/// dereferences a raw ring-3 VA directly, instead of going through
/// `copy_from_user`/`copy_to_user`, faults immediately with `SUM=0` rather
/// than silently succeeding — same protection, opposite default polarity
/// (aarch64's `PAN=1` "protected", riscv64's `SUM=0` "protected").
pub const SSTATUS_SUM: usize = 1 << 18;

/// O3.2 (owner decision, PAN/SUM discipline): RAII guard setting `sstatus.
/// SUM` for its lifetime, clearing it on drop — the riscv64 twin of
/// `arch-aarch64::sysregs::UserAccess`. `csrs`/`csrc` are single
/// instructions (no read-modify-write round trip needed, unlike a plain
/// `write_sstatus`).
pub struct UserAccess;

impl UserAccess {
    #[inline(always)]
    pub fn enable() -> Self {
        unsafe {
            core::arch::asm!("csrs sstatus, {0}", in(reg) SSTATUS_SUM, options(nostack));
        }
        UserAccess
    }
}

impl Drop for UserAccess {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe {
            core::arch::asm!("csrc sstatus, {0}", in(reg) SSTATUS_SUM, options(nostack));
        }
    }
}

// ---- sie bit definitions ----

pub const SIE_SSIE: usize = 1 << 1;
pub const SIE_STIE: usize = 1 << 5;
pub const SIE_SEIE: usize = 1 << 9;

// ============================================================
// AIA (Smaia/Ssaia) indirect CSR access
// ============================================================
//
// `siselect`/`sireg`/`stopei` are written as numeric CSR addresses, not
// mnemonics, for the same reason `arch/riscv64/src/irq/clint.rs` writes
// `csrw 0x14d` for `stimecmp`: the mnemonic needs the Ssaia (or Sstc)
// target feature, which this build's RUSTFLAGS do not enable. Whether the
// hart implements the CSR is a runtime question: the only caller,
// `arch/riscv64/src/irq/imsic.rs`, is reached only after the DTB described a
// `riscv,imsics` group.
//
// Addresses as in Linux `arch/riscv/include/asm/csr.h`: CSR_SISELECT 0x150,
// CSR_SIREG 0x151, CSR_STOPEI 0x15c; TOPEI_ID_SHIFT 16, TOPEI_ID_MASK 0x7ff.

/// `siselect` CSR address.
pub const CSR_SISELECT: usize = 0x150;
/// `sireg` CSR address — indirect data window selected by `siselect`.
pub const CSR_SIREG: usize = 0x151;
/// `stopei` CSR address — Supervisor Top External Interrupt (IMSIC claim).
pub const CSR_STOPEI: usize = 0x15c;

/// Bit position of the interrupt identity field within a `stopei` read.
pub const TOPEI_ID_SHIFT: u32 = 16;
/// Mask (already shifted down) of the interrupt identity field — 11 bits.
pub const TOPEI_ID_MASK: u32 = 0x7ff;

/// Select an IMSIC indirect register for the following [`read_sireg`] /
/// [`write_sireg`]. The select/access pair may be interrupted: no interrupt
/// handler in this kernel writes `siselect` (the external-interrupt claim
/// uses `stopei` only), so the selection survives.
#[inline(always)]
pub fn write_siselect(val: usize) {
    unsafe { core::arch::asm!("csrw 0x150, {}", in(reg) val, options(nostack)) };
}

#[inline(always)]
pub fn read_sireg() -> usize {
    let val: usize;
    unsafe { core::arch::asm!("csrr {}, 0x151", out(reg) val) };
    val
}

#[inline(always)]
pub fn write_sireg(val: usize) {
    unsafe { core::arch::asm!("csrw 0x151, {}", in(reg) val, options(nostack)) };
}

/// Atomically read `stopei` and write it back to 0 in one instruction
/// (`csrrw rd, stopei, x0`) — the IMSIC claim: returns the raw register
/// value (caller extracts the identity with [`TOPEI_ID_SHIFT`] /
/// [`TOPEI_ID_MASK`]), or 0 if nothing is pending (bit pattern the spec
/// defines as "no interrupt", same sentinel `plic::claim` already uses).
#[inline(always)]
pub fn swap_stopei_zero() -> usize {
    let val: usize;
    unsafe { core::arch::asm!("csrrw {}, 0x15c, zero", out(reg) val) };
    val
}
