// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 entry — defines the kernel-side TrapFrame layout
//! that aarch64-native trap-vector asm will populate.
//!
//! The asm (VBAR_EL1 vector table, save x0..x30 + SPSR_EL1 +
//! ELR_EL1 + FAR_EL1 + ESR_EL1) lives in `arch_aarch64::boot`
//! today as a demo trampoline; once Stage 5 wires this entry
//! module into the real kernel boot path, the same asm will
//! drop into [`trap_entry`] with `&mut TrapFrame`.

#![cfg(target_arch = "aarch64")]

// BOARD_RPI5 is selectable in `make config` so the target and its notes
// live with the other boards, but nothing below drives it yet.
#[cfg(feature = "rpi5")]
compile_error!("Raspberry Pi 5 is not ported: it needs a GICv2 (GIC-400) irqchip backend, \
the BCM2712 PL011 debug UART as console and firmware boot (kernel8.img); see BOARD_RPI5's help");

use super::{TrapClass, TrapContext};

pub mod fp_lazy;

// Through the facade, same convention `aarch64_early_mmu_init` below
// already uses for `mmu_setup` — see that function's comment for why this
// resolves on the real `aarch64-unknown-none` target and is never reached
// on a host build (the kernel binary is never built for the host triple).

// ─────────────────────────────────────────────────────────────────────────
// Early identity map — MMU on before the first atomic (Item 2 Stage 5,
// task 2)
// ─────────────────────────────────────────────────────────────────────────

/// Called from `boot.S`, once, after `.bss` is cleared and before `bl
/// kernel_main` — see that file's comment on why it must run there and
/// not inside `kernel_main`.
///
/// Builds a temporary identity map (RAM Normal cacheable, low-GiB MMIO
/// Device) and turns the MMU on via
/// `azos_arch_aarch64::mmu_setup::enable_identity_map` — the same
/// function `tests/qemu/aarch64-smoke` already boots through (single source
/// for the MAIR/TCR encoding, per this task's brief; nothing here
/// re-derives it). This is deliberately a BOOTSTRAP mapping, not the
/// kernel's real page tables: `kernel_main` later builds those properly
/// through `crates/core/mm::vmm` (PMM-backed, W^X-enforced, portable across
/// ISAs via `arch-api::Mmu`) and switches `TTBR0_EL1` to them once the
/// allocator exists. Until then, this coarse RWX identity map is what
/// lets `kernel_main`'s very first `kprintln!` — which takes a spinlock,
/// i.e. an atomic — run without touching Device memory with an exclusive
/// access (CONSTRAINED UNPREDICTABLE per the ARM ARM with the MMU off).
///
/// No lock, no atomic, no allocation: only static page tables it owns
/// exclusively (this function runs once, on the primary PE, before
/// anything else can reach them) and CPU system-register writes — safe
/// to run this early.
///
/// `base_pa` is `azos_drv_base::platform::hw::RAM_BASE` (0x4000_0000
/// on QEMU `virt`), written as a literal rather than imported: this
/// function is reached from `boot.S` before `kernel_main` does its own
/// platform setup, and duplicating one already-`pub const` platform fact
/// as a literal (with the cross-check below) is preferable to growing
/// this leaf's dependency surface for one constant this early in boot.
#[unsafe(no_mangle)]
pub extern "C" fn aarch64_early_mmu_init() {
    // Through the `azos_arch` facade, not `azos_arch_aarch64`
    // directly: the kernel crate depends on the facade (it is already
    // built for both ISAs through it), and the facade re-exports this
    // module verbatim (`pub use azos_arch_aarch64::*` in
    // `crates/core/arch/src/lib.rs`) when `target_arch = "aarch64"`.
    use azos_arch::mmu_setup::{enable_identity_map, IdentityMapConfig, PageTable};

    const RAM_BASE: u64 = 0x4000_0000;
    const _: () = assert!(
        RAM_BASE as usize == azos_drv_base::platform::hw::RAM_BASE,
        "aarch64_early_mmu_init's RAM_BASE literal drifted from platform::hw::RAM_BASE",
    );

    static mut L1: PageTable = PageTable::zero();
    static mut L2: PageTable = PageTable::zero();
    static mut L3: PageTable = PageTable::zero();

    // config/Kconfig.arch AARCH64_PAGE_*: a PE that does not implement the
    // granule this kernel was built for never translates once the MMU is on,
    // and nothing could be printed after that. Say so now, on the PL011 by
    // physical address (MMU off: the access is to Device memory), and stop.
    if !azos_arch::mmu_setup::granule_supported() {
        early_halt(b"\r\n[AARCH64-GRANULE] FATAL: this CPU does not implement the translation \
granule the kernel was built for (ID_AA64MMFR0_EL1.TGran); halting\r\n");
    }

    unsafe {
        enable_identity_map(IdentityMapConfig {
            l1: &raw mut L1,
            l2: &raw mut L2,
            l3: &raw mut L3,
            base_pa: RAM_BASE,
            user_code_pa: None,
            user_stack_pa: None,
        });
    }
    // `enable_identity_map` grants EL0 FP (`FPEN = 0b11`); put this hart in
    // the lazy-FP resting state (`fp_lazy`'s module doc). Runs on every hart:
    // boot.S calls this function on the primary and on each secondary.
    let cpacr = fp_lazy::set_resting_state();
    let hart = azos_sched::smp::current_cpu_id();
    if let Some(slot) = CORE_CPACR.get(hart) {
        slot.store(cpacr, Ordering::Release);
    }
}

/// Print `msg` on the PL011 with the MMU still off, then park this PE. For
/// the one failure that happens before any console exists.
fn early_halt(msg: &[u8]) -> ! {
    let base = azos_drv_base::platform::hw::UART_BASE;
    for &byte in msg {
        // UARTFR.TXFF (bit 5): wait for room, then UARTDR.
        while unsafe { core::ptr::read_volatile((base + 0x18) as *const u32) } & (1 << 5) != 0 {}
        unsafe { core::ptr::write_volatile(base as *mut u32, byte as u32) };
    }
    loop {
        unsafe { core::arch::asm!("wfe", options(nomem, nostack)) };
    }
}

/// `CPACR_EL1` read back on each hart after its last boot-time writer
/// (`aarch64_early_mmu_init`, then `aarch64_secondary_mmu_init` on the
/// secondaries). Reported by `boot_hooks`; anything but `FPEN = 0b01` there
/// means EL0 could use FP without trapping, i.e. without ever being saved.
pub static CORE_CPACR: [AtomicU64; crate::MAX_HARTS] =
    [const { AtomicU64::new(0) }; crate::MAX_HARTS];

/// Called from `boot.S`, once, right after `aarch64_early_mmu_init` — the
/// aarch64 parity program's TTBR1 migration, first wave. Builds a
/// STANDALONE alias table (own L1/L2/L3, separate from
/// `aarch64_early_mmu_init`'s bootstrap identity map and from
/// `crates/core/mm::vmm`'s real kernel table) mapping the same RAM window at
/// `base_pa | KERNEL_VA_OFFSET`, installs it into `TTBR1_EL1`, and turns
/// on TTBR1 walks. See `azos_arch::mmu_setup::enable_ttbr1_alias`'s
/// own doc for exactly what this does and does not change — in short:
/// TTBR0_EL1 and everything that already runs through it (the kernel's
/// own execution, `crates/core/mm`'s kernel table, every user page table) is
/// completely unaffected. This proves the TCR_EL1/TTBR1_EL1 encoding a
/// later wave needs to actually move the kernel here.
///
/// No lock, no atomic — same "safe before the first atomic" reasoning as
/// `aarch64_early_mmu_init`; this runs a few instructions after it, still
/// well before `kernel_main`'s first `kprintln!`.
#[unsafe(no_mangle)]
pub extern "C" fn aarch64_early_ttbr1_alias() {
    use azos_arch::mmu_setup::{enable_ttbr1_alias, PageTable, Ttbr1AliasConfig};

    const RAM_BASE: u64 = 0x4000_0000;

    static mut L1: PageTable = PageTable::zero();
    static mut L2: PageTable = PageTable::zero();
    static mut L3: PageTable = PageTable::zero();

    unsafe {
        enable_ttbr1_alias(Ttbr1AliasConfig {
            l1: &raw mut L1,
            l2: &raw mut L2,
            l3: &raw mut L3,
            base_pa: RAM_BASE,
        });
    }
    // `enable_ttbr1_alias` publishes `azos_arch::mmu_setup::
    // TTBR1_BOOT_VALUE`/`TCR_BOOT_VALUE` itself — see that function's own
    // doc. `kernel_main`'s `[AARCH64-TTBR1]` marker reads those directly;
    // `crates/core/sched`'s post-reap check reads `TTBR1_BOOT_VALUE` too (a
    // cross-crate reader, which is why it lives in `arch-aarch64` and not
    // here in the `kernel` crate).
}

/// A fixed, distinctive constant living at a known LOW virtual address
/// (this static's own link address — the kernel is still identity-mapped
/// low VA==PA at this milestone). [`ttbr1_alias_verify`] reads it back a
/// SECOND time through the TTBR1 alias (`this address | KERNEL_VA_OFFSET`)
/// and compares: a mismatch means the alias table maps the wrong physical
/// page, the wrong permissions, or nothing at all (a translation fault,
/// caught separately — see that function's doc).
#[unsafe(no_mangle)]
pub static TTBR1_ALIAS_CANARY: u64 = 0xC0FF_EE15_A11A_5000;

/// Read [`TTBR1_ALIAS_CANARY`] through its low-VA identity address and
/// again through the TTBR1 alias (`low_va | KERNEL_VA_OFFSET`), and report
/// whether they agree. Called once by `kernel_main` after
/// [`aarch64_early_ttbr1_alias`] has run.
///
/// **Why this has to be a live read, not a structural argument.** "The L3
/// loop wrote the right physical address" and "TTBR1_EL1 points at that
/// L1" are two different claims from two different pieces of code
/// (`enable_ttbr1_alias`'s L1/L2/L3 fill vs. its own `write_ttbr1_el1`
/// call) — a bug that breaks either one leaves the OTHER looking correct
/// under a register-only readback. Only an actual load through the high
/// address exercises the whole path: TCR's T1SZ/TG1 select TTBR1 for that
/// VA at all, the walk reaches the right leaf, and the leaf's physical
/// address and permissions are the ones the canary lives at. Returns
/// `(low_value, high_value, matched)`.
pub fn ttbr1_alias_verify() -> (u64, u64, bool) {
    let low_va = &TTBR1_ALIAS_CANARY as *const u64 as u64;
    let high_va = low_va | azos_arch::mmu::KERNEL_VA_OFFSET;
    let low_value = unsafe { core::ptr::read_volatile(low_va as *const u64) };
    let high_value = unsafe { core::ptr::read_volatile(high_va as *const u64) };
    (low_value, high_value, low_value == high_value && low_value == TTBR1_ALIAS_CANARY)
}

/// Called from `boot.S`'s `_aarch64_secondary_entry`, once per secondary
/// core, with that core's own SP already live (a stack slot from
/// `aarch64_secondary_stacks` in `kernel/src/main.rs`) and BEFORE that
/// core's first atomic — same constraint `aarch64_early_mmu_init` exists to
/// satisfy on the primary, see this module's `SECONDARY_TTBR0_PA` doc for
/// why the payload has to arrive as a plain (non-exclusive) load rather than
/// through `azos_mm::vmm::kernel_pagetable()`'s own `Mutex`.
///
/// Attaches this PE's `TTBR1_EL1` to the REAL kernel page table
/// ([`SECONDARY_TTBR1_PA`]) — the same table hart 0's own `TTBR1_EL1` holds
/// after `azos_mm::vmm::enable_paging`, carrying W^X, NX-outside-image
/// and the stack guards. U01-1 (audit): this used to attach
/// `azos_arch::mmu_setup::TTBR1_BOOT_VALUE`, the early-boot alias
/// `aarch64_early_ttbr1_alias` builds — a flat RWX mapping with none of
/// those protections, and never replaced on THIS register because the
/// primary's own `TTBR1_EL1` switch (`ARCH.switch_kernel_pt`, banked per PE)
/// cannot reach a PE that has not started yet. Falls back to the alias only
/// if [`SECONDARY_TTBR1_PA`] has not been published (`0` — should not
/// happen once `boot_hooks::arch_hardware_init` has run, which it always
/// has by the time any secondary reaches this call), so a secondary still
/// gets SOME upper-half mapping rather than none.
#[unsafe(no_mangle)]
pub extern "C" fn aarch64_secondary_ttbr1_attach() {
    // TTBR1_EL1 and TCR_EL1 are BANKED PER PE: the primary's write reaches
    // only the primary. A secondary that jumps to a high VA without this has
    // no upper-half translation at all, and the fault it takes cannot be
    // reported — its own handler needs the mapping that is missing.
    //
    // TCR_EL1's upper-half fields (T1SZ/TG1/IRGN1/ORGN1/SH1/EPD1) do not
    // change between the alias and the real table — `enable_paging`'s
    // `switch_kernel_pt` writes only `TTBR1_EL1` (`crates/core/arch-aarch64::
    // api_impl::Mmu::switch_kernel_pt`) — so `TCR_BOOT_VALUE` (published once,
    // at the alias install) still describes the live register correctly;
    // only the TTBR1 base address needs the post-`enable_paging` value.
    let ttbr1 = match SECONDARY_TTBR1_PA.load(Ordering::Acquire) {
        0 => azos_arch::mmu_setup::TTBR1_BOOT_VALUE.load(Ordering::Acquire),
        pa => pa as u64,
    };
    let tcr = azos_arch::mmu_setup::TCR_BOOT_VALUE.load(Ordering::Acquire);
    if ttbr1 == 0 || tcr == 0 {
        return;
    }
    unsafe {
        azos_arch::sysregs::write_tcr_el1(tcr);
        core::arch::asm!("msr TTBR1_EL1, {0}", in(reg) ttbr1, options(nomem, nostack));
        core::arch::asm!("isb", options(nomem, nostack));
        azos_arch::sysregs::tlbi_vmalle1is();
        core::arch::asm!("isb", options(nomem, nostack));
    }
    // U01-1: publish a REAL readback of TTBR1_EL1, for the boot CPU's own
    // check — see CORE_TTBR1's own doc. `current_cpu_id()` is valid here:
    // `boot.S` publishes TPIDR_EL1 before this call (see that file's own
    // comment).
    let hart = azos_sched::smp::current_cpu_id();
    if let Some(slot) = CORE_TTBR1.get(hart) {
        slot.store(azos_arch::sysregs::read_ttbr1_el1(), Ordering::Release);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn aarch64_secondary_mmu_init() {
    let ttbr0_pa = SECONDARY_TTBR0_PA.load(Ordering::Acquire);
    unsafe {
        azos_arch::mmu_setup::enable_kernel_map(ttbr0_pa);
    }
    // `enable_kernel_map` grants EL0 FP again; back to the lazy-FP resting
    // state (see `aarch64_early_mmu_init`).
    let cpacr = fp_lazy::set_resting_state();
    // U01-2: publish a REAL readback (not the value we asked
    // `enable_kernel_map` to install) for the boot CPU's own check — see
    // CORE_TTBR0's own doc.
    let hart = azos_sched::smp::current_cpu_id();
    if let Some(slot) = CORE_TTBR0.get(hart) {
        slot.store(azos_arch::sysregs::read_ttbr0_el1(), Ordering::Release);
    }
    if let Some(slot) = CORE_CPACR.get(hart) {
        slot.store(cpacr, Ordering::Release);
    }
}

/// Register count for the AArch64 general-purpose file — x0..x30
/// (x31 is sp/zr depending on context, saved separately).
const NUM_GPR: usize = 31;

/// AArch64-native TrapFrame.  Layout chosen so the asm saves
/// registers in order: GPRs x0..x30 → ELR_EL1 (return PC) →
/// SPSR_EL1 (saved status) → SP_EL0 (user SP) → FAR_EL1 (fault
/// addr) → ESR_EL1 (cause) → vector index.
///
/// **304 bytes, a multiple of 16, and the padding is load-bearing.** The 37
/// scalar fields are 296 bytes; `_pad` brings that to 304. AArch64 faults on
/// a misaligned SP at EL1 (`EC=0x26`), so a trap entry doing `sub sp, sp,
/// #size_of::<TrapFrame>()` with a non-16-multiple would take an alignment
/// exception on its way into the handler that exists to report exceptions —
/// this is why the asserts below exist, not just the padding.
///
/// **No FP/SIMD state.** The kernel is soft-float and never touches
/// V0-V31/FPSR/FPCR, so a trap leaves the interrupted user's FP registers
/// in the hardware untouched; they are saved lazily, only when another task
/// needs the registers (`fp_lazy`'s module doc). The frame used to carry the
/// full 528-byte FP file, saved and restored on every trap.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct TrapFrame {
    pub regs:    [u64; NUM_GPR], // x0..x30
    pub elr_el1: u64,            // saved PC
    pub spsr_el1: u64,           // saved PSTATE (used for came_from_user)
    pub sp_el0:  u64,            // user-mode stack pointer
    pub far_el1: u64,            // faulting VA on page faults
    pub esr_el1: u64,            // exception syndrome (cause)
    pub vector:  u64,            // vector index (synch/irq/fiq/serr)
    /// Keeps the frame a multiple of 16 bytes. Never read.
    pub _pad:    u64,
    /// Zero-sized and never read. Kept only because `kernel/src/main.rs`
    /// injects `offset_of!(TrapFrame, fpstate)` into `trap_entry.S`
    /// (`TF_OFF_FPSTATE`, no longer used by any instruction); remove it
    /// together with that line.
    pub fpstate: [u64; 0],
}

// The frame is what the trap asm reserves on the stack, so its size is an ABI
// between this struct and `entry/aarch64/asm/trap_entry.S`. Both properties are
// asserted, because the second one is the one that fails at runtime and the
// first is the one a reader checks.
const _: () = assert!(
    core::mem::size_of::<TrapFrame>() == 304,
    "aarch64 TrapFrame changed size: update entry/aarch64/asm/trap_entry.S's \
     frame reservation and this assertion together",
);
const _: () = assert!(
    core::mem::size_of::<TrapFrame>() % 16 == 0,
    "aarch64 TrapFrame must be a multiple of 16: SP is 16-byte aligned at EL1 \
     and a misaligned SP faults with EC=0x26 inside the trap entry itself",
);

/// Vector-index encoding written by the asm wrapper. Mirrors
/// the ARM vector table slots (§D1.10).
pub const VEC_SYNC_CURRENT_EL_SP0: u64 = 0;
pub const VEC_IRQ_CURRENT_EL_SP0:  u64 = 1;
pub const VEC_SYNC_LOWER_EL:        u64 = 4; // user → kernel SVC / fault
pub const VEC_IRQ_LOWER_EL:         u64 = 5;

/// ESR_EL1.EC field — bits [31:26].  We only categorise a few.
const ESR_EC_SHIFT:       u64 = 26;
const ESR_EC_MASK:        u64 = 0x3F;
const EC_FP_ACCESS:       u64 = 0x07; // FP/SIMD access trapped by CPACR_EL1.FPEN
const EC_SVC64:           u64 = 0x15; // SVC from aarch64 EL0
const EC_INSTR_ABORT_EL0: u64 = 0x20;
const EC_INSTR_ABORT_EL1: u64 = 0x21;
const EC_DATA_ABORT_EL0:  u64 = 0x24;
const EC_DATA_ABORT_EL1:  u64 = 0x25;

/// SPSR_EL1.M[3:0] = 0 ⇒ came from EL0 (user).
const SPSR_M_MASK: u64 = 0xF;

/// AArch64 syscall calling convention: x8 = syscall number,
/// x0..x5 = arguments, x0 = return value.
const REG_X0: usize = 0;
const REG_X8: usize = 8;
const MAX_SYSCALL_ARGS: usize = 6;

impl TrapContext for TrapFrame {
    #[inline]
    fn cause(&self) -> usize { self.esr_el1 as usize }

    fn class(&self) -> TrapClass {
        if self.vector == VEC_IRQ_CURRENT_EL_SP0 || self.vector == VEC_IRQ_LOWER_EL {
            return TrapClass::Interrupt;
        }
        let ec = (self.esr_el1 >> ESR_EC_SHIFT) & ESR_EC_MASK;
        match ec {
            EC_SVC64 => TrapClass::Syscall,
            EC_INSTR_ABORT_EL0 | EC_INSTR_ABORT_EL1
            | EC_DATA_ABORT_EL0 | EC_DATA_ABORT_EL1 => TrapClass::PageFault,
            _ => TrapClass::OtherException,
        }
    }

    /// AArch64 IRQs are read from GICv3 ICC_IAR1_EL1, not from
    /// the trap frame. The vector asm reads IAR1 and stores it
    /// into `esr_el1` as a convenience (`esr_el1` is unused for
    /// IRQ entries on aarch64). The shared handler treats this
    /// as "IRQ number" for portability.
    #[inline]
    fn irq_number(&self) -> usize { self.esr_el1 as usize }

    #[inline]
    fn fault_addr(&self) -> usize { self.far_el1 as usize }

    #[inline]
    fn pc(&self) -> usize { self.elr_el1 as usize }

    #[inline]
    fn set_pc(&mut self, pc: usize) { self.elr_el1 = pc as _; }

    #[inline]
    fn user_sp(&self) -> usize { self.sp_el0 as usize }

    #[inline]
    fn came_from_user(&self) -> bool {
        // SPSR_EL1.M[3:0] = 0 ⇒ EL0t (user). Anything else
        // (4, 5, 8, 9, 12, 13) means EL1+ kernel context.
        (self.spsr_el1 & SPSR_M_MASK) == 0
    }

    #[inline]
    fn syscall_number(&self) -> usize { self.regs[REG_X8] as usize }

    #[inline]
    fn syscall_arg(&self, n: usize) -> usize {
        debug_assert!(n < MAX_SYSCALL_ARGS);
        self.regs[REG_X0 + n] as usize
    }

    #[inline]
    fn set_syscall_return(&mut self, v: usize) {
        self.regs[REG_X0] = v as _;
    }
}

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

// ─────────────────────────────────────────────────────────────────────────
// Phase 2 trap policy — GICv3 IRQ dispatch, an EL1 `svc` self-test, and the
// FP-survives-interrupt canary. Everything else is still "report and park"
// (see `unhandled_trap`).
// ─────────────────────────────────────────────────────────────────────────

/// Ticks delivered by the EL1 virtual timer (PPI 27) since
/// [`arm_periodic_timer`] armed it, summed across every core. Kept exactly
/// as Phase 2 left it (a single global counter) — Phase 2's own self-test
/// (svc round-trip / N-ticks-in-bounded-time / FP-survives-interrupt) reads
/// it before any secondary exists, so widening its MEANING here would be a
/// silent behavior change to code this task must not disturb. Per-core
/// counts for Phase 4's SMP markers live in [`TICK_PER_HART`] instead.
/// The PPI every core enables for its tick: the virtual timer's
/// (`gic::PPI_VIRT_TIMER`, which [`handle_irq`] dispatches on). Under the
/// gate canary `a64clk-ppi-canary` it is the PHYSICAL timer's instead while
/// `CNTV_*` is what gets programmed, so the tick never arrives and the
/// boot parks right after the svc self-test (see `a64clk-ppi-canary`)
/// and never prints `[TIMER] ticks:`.
pub const TIMER_PPI_ENABLED: u32 = if cfg!(feature = "a64clk-ppi-canary") {
    azos_arch::gic::PPI_EL1_PHYS_TIMER
} else {
    azos_arch::gic::PPI_VIRT_TIMER
};

pub static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Live `CNTFRQ_EL0` value, published once by `kernel_main` right after it
/// reads it (see that function's `live_hz` and `install_vdso` call) so
/// [`handle_irq`] can convert `CNTVCT_EL0` ticks to milliseconds for the
/// vDSO page (M01) without re-reading a system register on every IRQ. 0
/// until published — `handle_irq` treats that as "not ready yet" and skips
/// the vDSO update for that tick rather than dividing by it.
pub static VDSO_TIMEBASE_HZ: AtomicU64 = AtomicU64::new(0);

/// Ticks delivered on each core, indexed by `current_cpu_id()` — Phase 4's
/// "each core took at least N ticks" marker reads this back per hart after a
/// bounded wait. `MAX_HARTS` (not `MAX_CPUS`): mirrors every other per-hart
/// table in `kernel/src/main.rs` (`aarch64_irq_stacks`,
/// `aarch64_secondary_stacks`), all sized by the boot-time hart count rather
/// than the scheduler's (smaller, `MAX_HARTS <= azos_sched::MAX_CPUS` is
/// asserted in `main.rs`) online-CPU count.
pub static TICK_PER_HART: [AtomicU64; crate::MAX_HARTS] =
    [const { AtomicU64::new(0) }; crate::MAX_HARTS];

/// Physical address of the LOW-half root every secondary attaches into its
/// OWN `TTBR0_EL1` — published by the boot CPU, read by every secondary's
/// `aarch64_secondary_mmu_init` BEFORE that secondary's own MMU is on.
///
/// U01-1/U01-2 (audit): this used to be `azos_mm::vmm::kernel_pagetable()`
/// — the SAME table now installed in `TTBR1_EL1` — published right after
/// `enable_paging()` but BEFORE `boot_hooks::arch_hardware_init` calls
/// `azos_mm::vmm::install_device_only_ttbr0()` a few lines later. A
/// secondary attaching that value ran with the whole kernel image (RAM
/// included) reachable by physical address through its own TTBR0 forever
/// — exactly the hole `install_device_only_ttbr0` exists to close on hart
/// 0. This is now published AFTER that call, holding the device-only
/// root's PA (recovered via `azos_arch::sysregs::read_ttbr0_el1()`,
/// since `install_device_only_ttbr0` returns a page count, not the root —
/// see that readback's own doc for why): every secondary's low half now
/// maps MMIO windows only, RAM unreachable by PA, same as hart 0's.
///
/// **Why a plain `AtomicUsize` and not a direct call on the secondary.**
/// `azos_mm::vmm::kernel_pagetable()`/the device-only root's own
/// accessor take a `Mutex` (a compare-exchange, an exclusive access), and
/// with THIS PE's own MMU still off every data access is Device-nGnRnE,
/// where an exclusive access is CONSTRAINED UNPREDICTABLE per the ARM ARM
/// (the same constraint `boot.S`'s "MMU on before the first atomic" header
/// comment documents for the primary path). A plain (non-exclusive)
/// `AtomicUsize` load compiles to an ordinary `LDR`/`LDAR` — ordinary
/// Device-memory reads are unaffected by that constraint — so this is safe
/// to read pre-MMU.
pub static SECONDARY_TTBR0_PA: AtomicUsize = AtomicUsize::new(0);

/// U01-1 (audit): physical address of the kernel's REAL page table to
/// attach into a secondary's `TTBR1_EL1` — published by the boot CPU right
/// after its OWN `TTBR1_EL1` is switched from the early-boot alias
/// (`azos_arch::mmu_setup::TTBR1_BOOT_VALUE`, see that static's own doc)
/// to `azos_mm::vmm::kernel_pagetable()` (`azos_mm::vmm::
/// enable_paging`'s `ARCH.switch_kernel_pt` call).
///
/// **Why this is a SEPARATE static from `TTBR1_BOOT_VALUE`, not that value
/// updated in place.** `TTBR1_BOOT_VALUE` is read a second time, much
/// later, by `boot_hooks::arch_hardware_init`'s own `[AARCH64-TTBR1]`
/// marker specifically to print what TTBR1 held AT BOOT (the alias) next
/// to what `sysregs::read_ttbr1_el1()` shows it holds NOW (the real table)
/// — that diagnostic's whole point is comparing the two, so overwriting
/// the "at boot" value would make it compare a value against itself.
///
/// Before this static is published (`0`), [`aarch64_secondary_ttbr1_attach`]
/// falls back to `TTBR1_BOOT_VALUE` — the alias — which is what every
/// secondary attached to before this fix (U01-1): the alias table is a flat
/// RWX identity mapping, so the W^X split, the NX-outside-image sweep and
/// the stack guards `boot_hooks::arch_hardware_init` applies to the REAL
/// kernel table (`crates/core/mm::vmm::KERNEL_PT`) covered hart 0 only. A
/// secondary that attaches the real table instead runs under the same
/// protections hart 0 does — one kernel page table, one set of
/// permissions, enforced on every PE.
pub static SECONDARY_TTBR1_PA: AtomicUsize = AtomicUsize::new(0);

/// The kernel's own `TTBR0_EL1` value (root physical address, ASID 0),
/// published at the same point as [`SECONDARY_TTBR0_PA`] above — but
/// `#[unsafe(no_mangle)]` so `context_switch.S` can read it directly by a
/// fixed symbol name (`adrp`/`ldr`, no FFI call), the same idiom
/// `trap_entry.S` already uses for `aarch64_irq_stacks`.
///
/// **Why this exists alongside `SECONDARY_TTBR0_PA`.** Every kernel task
/// (idle included) carries `task.task_satp == 0` — plain zero-init, never
/// written to anything else unless the task later gets a real user address
/// space. `context_switch.S`'s dispatch used to treat `task_satp == 0` as
/// "skip the `TTBR0_EL1` switch entirely, trust whatever is already
/// loaded" — correct on the milestone that comment was written for (every
/// task WAS a kernel task sharing one root, so `TTBR0_EL1` never changed
/// after boot), but Phase 6 gave user tasks their own `task_satp`, and
/// nothing ever taught the kernel-task ARM that "0" now means "must be the
/// KERNEL's root", not "whatever is already there". A hart that runs a
/// user task and is then dispatched to any kernel task — idle most often,
/// since it is what a hart falls back to — keeps that user task's
/// `TTBR0_EL1` loaded indefinitely. Once that user task exits and its page
/// table's physical frames are freed and reused (ipctest's own churn,
/// `crates/core/mm`), the hart is idling — and, worse, taking every subsequent
/// interrupt — under a dangling root: a translation that used to resolve
/// now walks reclaimed memory, and the exact instant it stops resolving
/// depends on what has since overwritten those frames. Measured directly
/// (temporary idle-loop/trap-entry instrumentation, since removed, aarch64
/// ipctest `-smp 2`): the frozen hart's own `TTBR0_EL1` at its last
/// idle-loop publish was a stale user root, not [`SECONDARY_TTBR0_PA`]'s
/// value, and the kernel's own vector
/// table VA (`0x40081200`, universally mapped under the real kernel root)
/// read back `Unmapped` under that stale table via the QEMU monitor's
/// `gva2gpa` on that CPU — the mechanism behind the aarch64 ipctest ~20%
/// SMP stall. `context_switch.S` now installs THIS value whenever the
/// incoming task's `task_satp == 0` and the live `TTBR0_EL1` does not
/// already match it, instead of trusting stale hardware state. `0` here
/// (not yet published, i.e. still early boot) keeps the old skip-only
/// behavior — `context_switch` is never called before `kernel_main`
/// publishes this, so that fallback is defense in depth, not a load-
/// bearing path.
///
/// U01-2 (audit): this used to be published (`azos_mm::vmm::
/// kernel_pagetable()`, the SAME table now in `TTBR1_EL1`) BEFORE
/// `boot_hooks::arch_hardware_init` calls `install_device_only_ttbr0()`,
/// and never updated afterward — so the first switch into an idle kernel
/// task (`task_satp == 0`) after `sched::start()` re-installed the FULL
/// kernel root into `TTBR0_EL1` on hart 0, undoing "RAM unreachable by PA"
/// within a few hundred ms of boot, no matter how clean the `[MM] Low half
/// is device-only` marker looked when it printed. Now published (same
/// place as [`SECONDARY_TTBR0_PA`], see that static's doc) with the
/// device-only root's PA instead, so the re-install context_switch.S
/// performs on the first idle dispatch reinstates the SAME device-only
/// table that was already there, not the one `install_device_only_ttbr0`
/// just replaced.
#[unsafe(no_mangle)]
pub static AARCH64_KERNEL_TTBR0: AtomicU64 = AtomicU64::new(0);

/// This core's MPIDR_EL1, published by each secondary right after its own
/// MMU is on (a plain store is safe post-MMU; nothing reads this before
/// then) — the boot CPU's SMP bring-up reads it back as the "each core
/// online with its MPIDR" marker, and canary (b) (no `TPIDR_EL1` write on
/// secondaries) is checked against `CORE_HART_ID` below, not this array,
/// since a wrong `TPIDR_EL1` does not change what `MPIDR_EL1` itself reads.
pub static CORE_MPIDR: [AtomicU64; crate::MAX_HARTS] =
    [const { AtomicU64::new(0) }; crate::MAX_HARTS];

/// This core's OWN read-back of `current_cpu_id()` (i.e. `TPIDR_EL1`),
/// published alongside [`CORE_MPIDR`]. Canary (b) — skip writing `TPIDR_EL1`
/// on secondaries — must fail exactly this marker: `CORE_HART_ID[hart_id]`
/// then reads back as `0` (whatever `TPIDR_EL1` resets to, on QEMU) instead
/// of `hart_id`, on every secondary except (coincidentally) hart 1's own
/// affinity-only checks. The boot CPU's readback loop reports `FAILED:` when
/// `CORE_HART_ID[h] != h`.
pub static CORE_HART_ID: [AtomicU64; crate::MAX_HARTS] =
    [const { AtomicU64::new(u64::MAX) }; crate::MAX_HARTS];

/// U01-1/U01-2 (audit): this core's OWN readback of `TTBR0_EL1`/`TTBR1_EL1`,
/// published right after [`aarch64_secondary_ttbr1_attach`] /
/// [`aarch64_secondary_mmu_init`] install them — the boot CPU's online-
/// readback loop compares these against [`SECONDARY_TTBR0_PA`] (the
/// device-only root, or the full kernel table if `install_device_only_
/// ttbr0` failed — see that static's doc) and `azos_mm::vmm::
/// kernel_pagetable()` (what [`SECONDARY_TTBR1_PA`] should hold), and
/// reports `FAILED:` on a mismatch. `u64::MAX` sentinel, same convention as
/// [`CORE_HART_ID`]: `0` is itself a value a fault could legitimately
/// report (an unset `TTBR0_EL1`/`TTBR1_EL1` reads as whatever reset left
/// it, not necessarily 0), so "never published" needs its own sentinel
/// rather than overloading a value the register can actually hold.
pub static CORE_TTBR0: [AtomicU64; crate::MAX_HARTS] =
    [const { AtomicU64::new(u64::MAX) }; crate::MAX_HARTS];
pub static CORE_TTBR1: [AtomicU64; crate::MAX_HARTS] =
    [const { AtomicU64::new(u64::MAX) }; crate::MAX_HARTS];

/// Set once a core has published [`CORE_MPIDR`]/[`CORE_HART_ID`] and armed
/// its own timer — the boot CPU's online-readback loop polls this rather
/// than a raw nonzero check on the two arrays above (hart 0's own `MPIDR_EL1`
/// legitimately reads `0`, indistinguishable from "not yet published").
pub static CORE_ONLINE: [AtomicBool; crate::MAX_HARTS] =
    [const { AtomicBool::new(false) }; crate::MAX_HARTS];

/// SGI(intid 0) receipts, indexed by the RECEIVING core's `current_cpu_id()`
/// — the cross-core IPI marker's readback target. Incremented in
/// [`handle_irq`]'s SGI arm, read by whichever core sent the probe SGI after
/// a bounded wait.
pub static SGI_RECEIVED: [AtomicU64; crate::MAX_HARTS] =
    [const { AtomicU64::new(0) }; crate::MAX_HARTS];

/// LPI receipts, indexed by `intid - azos_arch::gic::LPI_INTID_BASE`
/// (i.e. the ITS EventID an MSI-X vector was mapped to via
/// `azos_arch::its::ItsDriver::map_vector`) — the acceptance-test
/// counter for RFC-0046 stage 1a: "per-vector count printed and shown to
/// move" reads this, and the canary (unmap the device in the ITS, or skip
/// `MAPTI`) is exactly "this array stays all-zero forever" because
/// `handle_irq` below only ever increments a slot an actual LPI arrived
/// for. Sized to `azos_arch::its::MAX_EVENTS_PER_DEVICE` — stage 1a's
/// one collection/one device scope (see that module's doc); a caller
/// indexing past it is a driver bug, not a hardware event, so this bumps
/// nothing rather than panicking on an out-of-range EventID.
pub static LPI_VECTOR_COUNT: [AtomicU64; azos_arch::its::MAX_EVENTS_PER_DEVICE] =
    [const { AtomicU64::new(0) }; azos_arch::its::MAX_EVENTS_PER_DEVICE];

/// The PL011 console's SPI INTID, as the DTB gave it (`azos_dtb::
/// dtb_pl011_irq`), or 0 when the line was not wired (no DTB, no PL011
/// node, or its `reg` is not the UART this kernel drives). Published by
/// `boot_hooks::console_irq` BEFORE the GIC enables the line, so the
/// first interrupt already finds its arm in [`handle_irq`].
pub static PL011_RX_INTID: AtomicU32 = AtomicU32::new(0);
/// PL011 RX interrupts taken — riscv64's `irqchip::delivered(UART_IRQ)`
/// twin, printed at scheduler start (`[IRQ] PL011 INTID .. delivered ..`).
pub static PL011_RX_IRQS: AtomicU64 = AtomicU64::new(0);
/// Of those, how many dispatched a parked console reader (the shell's
/// `readline`), i.e. `wake_task_by_tid` returned true.
pub static PL011_RX_WAKES: AtomicU64 = AtomicU64::new(0);

/// Ticks between two virtual-timer deadlines, in `CNTFRQ_EL0` units. `0`
/// means "not armed yet" — the handler skips re-arming rather than program
/// a zero-length period, which would make the timer refire as fast as it
/// can be acknowledged. Set once by [`arm_periodic_timer`].
pub static TICK_PERIOD: AtomicU64 = AtomicU64::new(0);

/// `[base, top)` of this (single, this milestone) CPU's IRQ stack slot,
/// published by `kernel_main` (via [`set_irq_stack_bounds`]) before IRQs
/// are unmasked. Lets the interrupt path prove, from inside a live
/// handler, that `sp` really moved onto the dedicated slot
/// `_trap_common`/`trap_entry.S` switches to.
static IRQ_STACK_BASE: AtomicUsize = AtomicUsize::new(0);
static IRQ_STACK_TOP:  AtomicUsize = AtomicUsize::new(0);

/// One-shot latch pair: [`IRQ_STACK_PROBED`] gates the check to the FIRST
/// interrupt only (mirrors riscv64's `irq_stack_probe`'s `PROBED` swap);
/// [`IRQ_TOOK_OWN_STACK`] holds the result. `kernel_main` reads both AFTER
/// its tick-wait loop returns and prints the `[AARCH64-IRQSTACK]` marker
/// itself — the handler does not `kprintln!` anything (see the module
/// note below): this kernel's UART spinlock is not `lock_irqsave`d, and an
/// interrupt landing while `kernel_main` is already mid-`kprintln!` on the
/// same lock would deadlock the boot instead of merely losing a message.
static IRQ_STACK_PROBED:   AtomicBool = AtomicBool::new(false);
static IRQ_TOOK_OWN_STACK: AtomicBool = AtomicBool::new(false);

/// `svc #0`'s reply, written into `x0` by the handler and read back by
/// `kernel_main` after the instruction returns. Arbitrary but distinctive:
/// a caller that reads anything else knows the round trip (entry →
/// dispatch → `eret`) did not really happen, rather than merely resuming
/// at *some* address with whatever `x0` used to hold.
pub const SELFTEST_SVC_REPLY: u64 = 0x5E1F_7E57_0000_0000;

/// Pattern [`fp_survives_interrupt_probe`] loads into `v8` before waiting
/// out one or more ticks. `handle_irq` deliberately zeroes `v8` on every
/// IRQ (see its comment) — this value is what proves the interrupted
/// code's copy was never touched despite that.
pub const FP_PROBE_PATTERN: u64 = 0xC0FF_EE12_34AB_CDEF;

/// Publish this CPU's IRQ-stack bounds for [`handle_irq`]'s one-shot
/// probe. Call before unmasking IRQs.
pub fn set_irq_stack_bounds(base: usize, top: usize) {
    IRQ_STACK_BASE.store(base, Ordering::Relaxed);
    IRQ_STACK_TOP.store(top, Ordering::Relaxed);
}

/// Whether the IRQ-stack probe ran and, if so, whether `sp` was really
/// inside `[base, top)` at the time. `(false, _)` means no interrupt has
/// landed yet.
pub fn irq_stack_probe_result() -> (bool, bool) {
    (
        IRQ_STACK_PROBED.load(Ordering::Acquire),
        IRQ_TOOK_OWN_STACK.load(Ordering::Acquire),
    )
}

/// Arm the EL1 virtual timer for periodic ticks and record the period so
/// [`handle_irq`] can keep re-arming it. Call AFTER GIC distributor +
/// redistributor + CPU-interface init and `enable_ppi(0, TIMER_PPI_ENABLED)`, BEFORE
/// unmasking IRQs — `kernel_main` is the only caller.
pub fn arm_periodic_timer(period_ticks: u64) {
    use azos_arch::{Cpu, ARCH};
    TICK_PERIOD.store(period_ticks, Ordering::Relaxed);
    let now = ARCH.now_ticks();
    // Through `timebase`, which records what this core programmed: a task
    // blocking on a timer deadline compares against that record (wave 11).
    azos_drv_sys::timebase::program_at(0, now.wrapping_add(period_ticks));
}

/// Task 4c — prove FP/SIMD state survives an interrupt.
///
/// Loads [`FP_PROBE_PATTERN`] into `v8`, then busy-waits (via `wfi`) until
/// EITHER [`TICK_COUNT`] reaches `target_ticks` OR the live `CNTVCT_EL0`
/// reaches `deadline_cntvct` — whichever comes first, so a timer that ticks too slowly stops after
/// one deadline — then reads `v8` back. With the line never enabled (or
/// masked) there is no interrupt to leave the `wfi`, and the deadline is
/// never compared: the boot parks before this point (the tick check above
/// it) and this probe is not reached.
///
/// **Why one `asm!` block and not "set, then loop in Rust, then read".**
/// Splitting it across separate `asm!`/Rust statements gives the compiler
/// license to reuse the physical `v8` register for its own codegen in
/// between calls — nothing ties a bare `dup v8.2d, ...` to a Rust value
/// once that `asm!` block ends. A probe built that way could read back a
/// wrong value for a reason that has nothing to do with trap handling,
/// which is the opposite of what a canary is for. Keeping "set → wait →
/// read" as one block means the only thing that can touch `v8` in between
/// is a real hardware exception — exactly what this probes.
///
/// Returns `(v8.d[0], v8.d[1], final tick count)`. Pass = both lanes still
/// equal `FP_PROBE_PATTERN`.
#[inline(never)] // its own symbol: `tools/aarch64_fp_free_check.sh` allows it by name
pub fn fp_survives_interrupt_probe(target_ticks: u64, deadline_cntvct: u64) -> (u64, u64, u64) {
    let tick_ptr = &TICK_COUNT as *const AtomicU64 as *const u64;
    let out_lo: u64;
    let out_hi: u64;
    let final_ticks: u64;
    unsafe {
        core::arch::asm!(
            // Soft-float kernel: V registers are named on purpose here.
            ".arch_extension fp",
            ".arch_extension simd",
            "dup v8.2d, {pattern}",
            "80:",
            "wfi",
            "ldr {cur}, [{tick_ptr}]",
            "cmp {cur}, {target}",
            "b.hs 81f",
            "mrs {now}, CNTVCT_EL0",
            "cmp {now}, {deadline}",
            "b.lo 80b",
            "81:",
            "mov {lo}, v8.d[0]",
            "mov {hi}, v8.d[1]",
            pattern  = in(reg) FP_PROBE_PATTERN,
            tick_ptr = in(reg) tick_ptr,
            target   = in(reg) target_ticks,
            deadline = in(reg) deadline_cntvct,
            cur      = out(reg) final_ticks,
            now      = out(reg) _,
            lo       = out(reg) out_lo,
            hi       = out(reg) out_hi,
            options(nostack),
        );
    }
    (out_lo, out_hi, final_ticks)
}

/// GICv3 dispatch for a real IRQ (vector `VEC_IRQ_CURRENT_EL_SP0` or
/// `VEC_IRQ_LOWER_EL`) — tasks 2/3. Runs on this hart's dedicated IRQ
/// stack: `_trap_common` in `trap_entry.S` switches `sp` before calling
/// here for the interrupt vectors specifically (never for sync/syscall).
/// The frame itself stays on the INTERRUPTED stack regardless — only the
/// handler moves, same split riscv64's `trap_entry.S` documents.
fn handle_irq(_frame: &mut TrapFrame) {
    // One-shot "did I really run on the IRQ stack" probe.
    if !IRQ_STACK_PROBED.swap(true, Ordering::AcqRel) {
        let sp: usize;
        unsafe { core::arch::asm!("mov {0}, sp", out(reg) sp, options(nomem, nostack)); }
        let base = IRQ_STACK_BASE.load(Ordering::Relaxed);
        let top  = IRQ_STACK_TOP.load(Ordering::Relaxed);
        IRQ_TOOK_OWN_STACK.store(base != 0 && sp >= base && sp < top, Ordering::Release);
    }

    // No FP/SIMD here, and no handler may use any. The kernel is soft-float
    // and the trap path no longer saves V0-V31 for the interrupted code
    // (user FP state is saved lazily, on context switch), so a V register
    // touched here would be the interrupted user task's, silently
    // corrupted. `fp_survives_interrupt_probe` (boot) checks that `v8`
    // comes back intact across many timer IRQs; its canary is putting a
    // `movi v8.2d, #0` back at this spot (this used to be here, when the
    // trap path saved the full FP file and handlers were allowed FP).

    let intid = azos_arch::gic::iar1();
    const INTID_SPURIOUS: u32 = 1023;
    const INTID_EL1_VIRT_TIMER: u32 = azos_arch::gic::PPI_VIRT_TIMER; // PPI 27
    // SGI 0 — this kernel's cross-core IPI, both for the scheduler's own
    // cross-CPU wake doorbell (`crates/core/sched::scheduler::cpu_enqueue_locked`
    // → `arch-api::Interrupts::send_ipi` → `arch-aarch64::api_impl`'s
    // `ICC_SGI1R_EL1` write) and for Phase 4's own send/receive marker. RISC-V's
    // equivalent doorbell is `INT_SOFTWARE_S` (`kernel/src/trap/interrupt.rs`) — same
    // purpose, different mechanism (a CSR-pending bit there, a GIC SGI here).
    const INTID_IPI_SGI: u32 = 0;

    if intid == INTID_SPURIOUS {
        // GICv3 §4.2: a spurious read (nothing was actually pending) must
        // NOT be deactivated — there is nothing to EOI.
        return;
    }
    // Wave 15 (TRACE): the irq class, the GIC INTID; the exit record is the
    // scope's drop, at every return below.
    let _irq_scope = azos_trace::IrqScope::enter(intid);

    // console-splice-smoke: an interrupt-context kernel line on every
    // interrupt, not only the timer's (on this ISA the timer is the one that
    // fires steadily while the smoke runs) — except the console's own: since
    // wave 11 the PL011's TX interrupt refills the FIFO from the TX ring, and
    // a line printed from each refill is new TX work for the next one.
    #[cfg(feature = "console-splice-smoke")]
    if intid != PL011_RX_INTID.load(Ordering::Relaxed) {
        crate::console_splice_isr_print();
    }

    if intid == INTID_IPI_SGI {
        let hart = azos_sched::smp::current_cpu_id();
        if let Some(slot) = SGI_RECEIVED.get(hart) {
            slot.fetch_add(1, Ordering::Release);
        }
        // Mirrors the timer arm below: a cross-core wake only RAISES A FLAG
        // here — `handle_irq` runs on this hart's dedicated IRQ stack, and
        // `schedule()` can `context_switch()` away (see this file's own
        // comment on `TrapClass::Interrupt` for why that stack split
        // matters). `request_resched()` targets THIS core's own slot via
        // `current_cpu_id()`.
        request_resched();
        azos_arch::gic::eoir1(intid);
        return;
    }

    // The PL011 console's RX / RX-timeout interrupt (a level SPI routed to
    // the boot hart; see `boot_hooks::console_irq`). `PL011_RX_INTID` is
    // 0 when it was not wired, and no INTID that reaches this line is 0
    // (SGI 0 returned above), so an unwired line never matches.
    //
    // Drain, THEN EOI: the line is level on the PL011's RX FIFO level /
    // timeout status. `uart::irq_handler` empties the FIFO into the ring the
    // console readers (`uart::can_read`/`getc`/`try_getc`) use and clears
    // RXIC/RTIC; only then is the line low, so the EOI below does not let
    // the GIC re-pend the same interrupt (the timer arm's order, for the
    // same reason). No FP: the ring is bytes and atomics.
    //
    // A reader parked on input (the shell's `readline`) left its TID in
    // `uart`; wake it the way `net_msi_wake` wakes `net_poll_task` — a TID
    // wake of a `Timer` sleeper, which STAMPS instead when the task has not
    // committed to `Blocked` yet, so the arm-then-retest in `readline` has
    // no lost-wakeup window. Only raise the reschedule flag when a task was
    // actually dispatched; never `schedule()` from here (IRQ stack).
    //
    // The same SPI carries the console's TX interrupt (wave 11): the handler
    // refills the FIFO from the TX ring before the EOI, for the same reason.
    // Only RX work counts and wakes the reader.
    let pl011 = PL011_RX_INTID.load(Ordering::Relaxed);
    if intid == pl011 && pl011 != 0 {
        if azos_drv_sys::uart::irq_handler() {
            PL011_RX_IRQS.fetch_add(1, Ordering::Relaxed);
            // Wave 13: `^C` on a console lent to a Linux job is SIGINT to
            // that job (lock-free posts).
            if azos_drv_sys::uart::take_intr() {
                azos_syscall::linux::console_signal(2);
            }
            let tid = azos_drv_sys::uart::rx_waiter_take();
            if tid != 0 && azos_sched::scheduler::wake_task_by_tid(
                tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)))
            {
                PL011_RX_WAKES.fetch_add(1, Ordering::Relaxed);
                request_resched();
            }
        }
        azos_arch::gic::eoir1(intid);
        return;
    }

    if intid == INTID_EL1_VIRT_TIMER {
        // Re-arm BEFORE EOI, not after. PPI 27 is level-triggered on
        // CNTV_CTL_EL0.ISTATUS, which stays asserted until CNTV_CVAL_EL0
        // moves past CNTVCT_EL0 — EOI only deactivates the GIC's record of
        // the interrupt, not the timer line itself. EOI-then-rearm leaves
        // the line asserted for however long the rearm takes, and the GIC
        // re-pends it immediately: two "ticks" would fire back to back per
        // real period, corrupting every measurement this milestone takes
        // (tick count, elapsed time, the FP-probe deadline). Order matters
        // and is not an optimisation.
        //
        // This write is the next tick; the nearest timer sleeper, when it is
        // earlier, is programmed after the wake sweep below (wave 11
        // ONESHOT). Not folded into one write here: before the sweep the
        // nearest deadline is the one that just expired, and programming a
        // past instant would leave the line asserted.
        let period = TICK_PERIOD.load(Ordering::Relaxed);
        let mut now = 0u64;
        if period != 0 {
            use azos_arch::{Cpu, ARCH};
            now = ARCH.now_ticks();
            azos_drv_sys::timebase::program_at(0, now.wrapping_add(period));
        }
        let ticks = TICK_COUNT.fetch_add(1, Ordering::Release) + 1;
        let hart = azos_sched::smp::current_cpu_id();
        if let Some(slot) = TICK_PER_HART.get(hart) {
            slot.fetch_add(1, Ordering::Release);
        }

        // ── The safety watchdog, which this ISR used to skip entirely ──────
        //
        // riscv64's tick handler (`kernel/src/trap/interrupt.rs`, its `watchdog::tick()`
        // / `halt_if_panicked()` / `feed_from_timer_tick()` trio) calls all
        // three every tick. This one called none, and the four consequences
        // were one omission:
        //
        //   * `sys-wdt`'s timer-liveness check read a counter nobody fed, so
        //     it was inert on this ISA and said so out loud rather than
        //     passing silently (`crates/core/actuation/src/sys_wdt.rs`);
        //   * a hart that panicked did not stop THIS hart's actuators — on a
        //     machine whose whole thesis is authority over irreversible
        //     effects, that is the one that matters;
        //   * the hardware WDT was never fed, so `CONTROL_HEARTBEAT` gating
        //     had no effect here;
        //   * `hw_init()` was riscv64-only (fixed in `kernel_main`).
        //
        // **Why `watchdog::tick()` in ADDITION to this file's own
        // `TICK_COUNT`, rather than replacing it.** They are not the same
        // counter and cannot be merged: `TICK_COUNT`'s address is handed to
        // `wait_for_ticks` as a raw pointer to poll, and it feeds
        // `vdso_update`. `watchdog::TICK_COUNT` is the liveness counter
        // `sys-wdt` watches. Two readers, two lifetimes, one increment each.
        let _ = azos_actuation::watchdog::tick();

        // Order matters and mirrors riscv64: halt BEFORE feeding. A panicked
        // hart must stop actuators and park without kicking the WDT, so the
        // board resets cleanly instead of being kept alive by this ISR.
        azos_actuation::watchdog::halt_if_panicked();
        azos_actuation::watchdog::feed_from_timer_tick();

        // M01: update the vDSO timing page — mirrors riscv64's own tick
        // handler (`kernel/src/trap/interrupt.rs`, its "M01: Update vDSO timing page"
        // comment) calling `vdso_update(ticks, uptime_ms)` every tick. `now`
        // is `CNTVCT_EL0` (raw counter units); `VDSO_TIMEBASE_HZ` converts
        // it to milliseconds the same way riscv64 converts its own
        // `timebase::now()` — divide by (Hz / 1000). Skipped while `now ==
        // 0` (timer not armed on this core yet, same guard the
        // `wake_expired_timers` call below uses) or while `VDSO_TIMEBASE_HZ`
        // has not been published yet (`kernel_main` publishes it once,
        // right after `install_vdso`, before any user task can exec).
        let vdso_hz = VDSO_TIMEBASE_HZ.load(Ordering::Relaxed);
        if now != 0 && vdso_hz != 0 {
            let uptime_ms = now / (vdso_hz / 1000);
            azos_mm::vdso::vdso_update(ticks, uptime_ms);
            // Wave 6: the running task's own vDSO page — the riscv64 tick
            // handler makes the same call next to its `vdso_update`.
            azos_syscall::vdso_notify::vdso_task_tick(now);
        }

        // Phase 4 (SMP): wake any task blocked on `WaitReason::Timer` whose
        // deadline (in `ARCH.now_ticks()`/`CNTVCT_EL0` units — the same
        // clock `smp_migration_probe_task` below sleeps against) has passed.
        // Mirrors riscv64's own tick handler calling `wake_expired_timers`
        // (`kernel/src/trap/interrupt.rs`, its own AQ0 comment) — without this, a task
        // that blocks to sleep on this ISA would never wake, since nothing
        // else sweeps expired timers here. `now` is 0 only if `period == 0`
        // (timer not armed yet, `arm_periodic_timer` not yet called on this
        // core) — a real deadline is never `<= 0` in `CNTVCT_EL0` units this
        // far into boot, so the sweep is simply a no-op that tick.
        if now != 0 {
            azos_sched::wake_expired_timers(now);
        }

        // K-C25: deliver wakes that were stamped onto a task which then
        // parked (`Blocked` + the K-C24 wake-stamp bit, context fully saved)
        // before ever consuming the stamp — one confirmed contributor to the
        // aarch64 ipctest SMP stall (gate 148's one failing row; a second,
        // separate starvation shape in the ready-queue path is still open —
        // see the investigation notes). See
        // `crate::task::sched_word::reap_orphaned_stamp` in
        // `crates/core/sched/src/task.rs` for the exact race this recovers from:
        // `wake_transition`'s `!saved` arm stamps a `Blocked` task that is
        // still mid-`block_current()` (an "unswitched block" — the CAS to
        // `Blocked` won, but `context_switch.S` has not yet cleared
        // `context_saving`). For a one-shot wake — the fast-IPC client wake
        // in particular, `fast_ipc_reply` → `wake_fast_ipc_client_tid` —
        // there is no second wake coming to retry the dispatch, so a stamp
        // that lands in the window between `do_schedule`'s switch-away sweep
        // and `context_switch.S` clearing `context_saving` parks the task
        // forever: `Blocked` (not running, so it cannot consume its own
        // stamp) and `context_saving == false` (so no in-flight sweep will
        // either).
        //
        // riscv64 closed this on 2026-08-24 (K-C25) by sweeping for it once
        // per tick, right here, in its own timer ISR
        // (`kernel/src/trap/interrupt.rs`'s `handle_interrupt_inner` —
        // `reap_stamped_sleepers()`, called unconditionally every ~10 ms).
        // aarch64's own periodic timer IRQ (`INTID_EL1_VIRT_TIMER`, this same
        // arm) never got the same call — the race is in `crates/core/sched`,
        // completely ISA-agnostic, and equally reachable on both ISAs (this
        // was measured directly: a client task blocked with the state-word
        // pattern `reap_orphaned_stamp` targets, `Blocked | WAKE_STAMP`,
        // frozen for the rest of the run — one child that never rejoins the
        // race is exactly the "shortfall is a whole number of children"
        // signature in ipctest phase A). Not gated on `now != 0`: recovering
        // a stamped sleeper needs no clock reading, only the per-task state
        // words, so it is safe and cheap to run from tick 0 — before the
        // timer is even armed there are no tasks to find in this state.
        azos_sched::reap_stamped_sleepers();

        // M04: expire leases whose deadline has passed — riscv64's tick
        // handler (`kernel/src/trap/interrupt.rs`) has called `lease_tick`
        // since M04; this one never did, so on aarch64 a lease deadline was
        // never enforced (wave 11, LEASE3). Same drain: the lessors parked in
        // `lease_wait` are woken, and the lease worker removes the expired
        // mappings from task context. `now` is `CNTVCT_EL0`, the unit a
        // ring-3 lessor reads (`cntvct_el0`) to stamp its deadline; skipped
        // while the timer is not armed (`now == 0`), as the sweep above is.
        // `iter().take(n)`: see riscv64's comment on the slice-range panic.
        if now != 0 {
            let mut expired = [0u32; azos_ipc::MAX_LEASES];
            let n = azos_ipc::lease_tick(now, &mut expired);
            for &lessor_tid in expired.iter().take(n) {
                azos_sched::wq_wake_by_tid(lessor_tid);
            }
            if n != 0 {
                crate::tasks::wake_lease_worker();
            }
        }

        // Wave 11 ONESHOT (RFC-0052 §4.5): the nearest remaining timer
        // sleeper, when it is earlier than the tick programmed above — what
        // riscv64's handler gets from `set_next_tick_smart`. Without it this
        // handler programmed `now + period` unconditionally, and a sleeper on
        // a hart that stayed busy woke at the next tick (the `lat:` rows'
        // ~1790 of 2000 late periods). `oneshot-canary` compiles it out.
        #[cfg(not(feature = "oneshot-canary"))]
        if period != 0 {
            if let Some(d) = azos_sched::nearest_timer_deadline() {
                azos_drv_sys::timebase::arm_if_earlier(d);
            }
        }

        // Phase 3 (context switch + scheduler): a timer tick only RAISES A
        // FLAG here, spent later by `aarch64_trap_resched` — never call
        // `azos_sched::schedule()` from this function directly. `handle_irq`
        // runs on this hart's dedicated IRQ stack (`_trap_common` switched `sp`
        // before calling here — see this function's own doc comment), and
        // `schedule()` can `context_switch()` away, which parks the outgoing
        // task by saving ITS `sp` into its own `TaskContext`. A task parked
        // with `sp` pointing into a stack shared by every interrupt on this
        // hart is a task whose frame the next interrupt overwrites. Mirrors
        // riscv64's `request_resched`/`trap_resched` split
        // (`kernel/src/trap/interrupt.rs`) exactly, for the exact same reason.
        request_resched();
    }

    if intid >= azos_arch::gic::LPI_INTID_BASE {
        // An LPI never carries a "which collection" tag back through
        // ICC_IAR1_EL1 — only the physical INTID the MAPTI command
        // assigned. `map_vector`'s caller (kernel_main's PCI/virtio-net-pci
        // wiring, A2-main.diff) is what makes `intid - LPI_INTID_BASE`
        // line up with an EventID; this handler does not know or need to
        // know which PCI function or queue it came from.
        let slot = (intid - azos_arch::gic::LPI_INTID_BASE) as usize;
        if let Some(counter) = LPI_VECTOR_COUNT.get(slot) {
            counter.fetch_add(1, Ordering::Release);
        }
        // The virtio-pci NIC's vectors (kernel_main's `ItsRoute`, token =
        // LPI slot): count, open its RX gate, wake `net_poll_task`.
        if azos_drv_virtio::virtio::net::msi_irq(slot as u32) && crate::net_msi_wake() {
            request_resched();
        }
        azos_arch::gic::eoir1(intid);
        return;
    }

    // An SPI a ring-3 driver bound (`SYS_IRQ_BIND` / `SYS_PORT_BIND_TYPED`),
    // delivered mask-until-ACK — riscv64's dispatch pair, `irq_dispatch` +
    // `wake_by_irq` (`kernel/src/trap/interrupt.rs`'s `INT_EXTERNAL_S` arm), plus the
    // mask that a level line needs while ring 3 has not quietened its device
    // yet: without it the EOI below re-pends the line at once and this hart
    // takes it forever. The range test comes first so the timer tick, which
    // falls through to here, pays a compare and no load.
    //
    // Order is load-bearing: MASK (ICENABLER + RWP wait), then EOI, then
    // dispatch. Dispatch is what lets the driver run (on any PE) and ACK;
    // `SYS_DRV_IRQ_ACK`'s unmask (ISENABLER) therefore cannot be ordered
    // before this delivery's mask. Not EOImode=1 (priority drop here,
    // `ICC_DIR_EL1` at ACK): EOImode is per PE and would put a DIR write into
    // the timer, SGI, PL011 and LPI arms above, and the deactivate would have
    // to run on the PE that took the interrupt; `GICD_ISENABLER` is a
    // distributor register any PE can write.
    //
    // Both calls take `lock_irqsave` spinlocks (bindings, ports) and wake by
    // enqueueing — the PL011 arm's shape. No `schedule()` here (IRQ stack):
    // only the reschedule flag. No FP.
    if azos_arch::gic::user_spi_in_range(intid)
        && azos_arch::gic::user_spi_owned(intid)
    {
        #[cfg(not(feature = "irq-mask-canary"))]
        azos_arch::gic::disable_spi(intid);
        azos_arch::gic::eoir1(intid);
        // Bindings first: a wake-task binding's registered waiter is woken
        // by TID there, and must no longer be `Blocked` when the sweep runs
        // (see `irq_bind::irq_dispatch`).
        azos_ipc::irq_dispatch(intid);
        azos_sched::wake_by_irq(intid);
        request_resched();
        return;
    }

    azos_arch::gic::eoir1(intid);
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 3/4 — deferred reschedule + preemption proof, now per-core.
//
// Phase 3 (single-core) kept this as one plain `AtomicBool`, correct while
// hart 0 was the only core that could ever take a tick. Phase 4 starts real
// secondaries: with two cores each taking their own timer IRQ, a single
// shared flag lets hart 1's `swap(false)` in `aarch64_trap_resched` silently
// clear a reschedule hart 0's own tick had just requested — the request is
// lost, not merely delayed, because nothing re-sets it. `[AtomicBool;
// MAX_HARTS]` indexed by `current_cpu_id()` gives every core its own flag,
// mirroring riscv64's own per-hart `NEED_RESCHED` (`kernel/src/trap/interrupt.rs`)
// exactly — same reason, same shape.
static NEED_RESCHED: [AtomicBool; crate::MAX_HARTS] =
    [const { AtomicBool::new(false) }; crate::MAX_HARTS];

/// Gates `aarch64_trap_resched` from calling `azos_sched::schedule()`
/// before any task exists. **Not the same mechanism riscv64 uses** — that
/// kernel keeps `sie.STIE` (the timer interrupt enable bit itself) clear
/// until immediately before `sched::start()`, so no tick can fire early at
/// all. This kernel cannot reuse that trick: the timer is already armed and
/// IRQs are already unmasked by the time `kernel_main` reaches this task's
/// own self-tests (svc round-trip, N-ticks-in-bounded-time, the FP-survives-
/// interrupt probe) — all Phase 2 work this task must not disturb. So ticks
/// keep arriving and `NEED_RESCHED` keeps getting set throughout Phase 2;
/// this flag is what stops `aarch64_trap_resched` from acting on any of
/// them until `kernel_main` has actually created task A and B and is about
/// to call `azos_sched::start()`. Set exactly once, never cleared.
pub static SCHED_LIVE: AtomicBool = AtomicBool::new(false);

/// Times `aarch64_trap_resched` actually entered `azos_sched::schedule()`
/// (i.e. `SCHED_LIVE` was set and a pending tick was consumed) — the
/// Phase-3 preemption marker. Task A and B never call `task_yield()` or
/// block on anything; the ONLY way execution ever leaves one of their tight
/// loops is a tick reaching this counter and `schedule()` deciding to time-
/// slice. A nonzero count, together with both tasks' own iteration counters
/// having advanced, is the proof kernel_main's marker line reads back.
pub static PREEMPT_COUNT: AtomicU64 = AtomicU64::new(0);

/// Ask for a reschedule, on THIS core, on the way out of this trap.
/// `Release`/`AcqRel` (matching riscv64's own `request_resched`/
/// `trap_resched` exactly, `kernel/src/trap/interrupt.rs`): Phase 4 is genuinely
/// cross-core now — the store here can run on a different core than the
/// `swap` in `aarch64_trap_resched` reads it back on (an SGI-driven
/// reschedule request, or simply this core's own tick landing between two
/// different points in its trap-return path), where Phase 3's `Relaxed` was
/// still correct precisely because both sides were provably the same core.
fn request_resched() {
    let hart = azos_sched::smp::current_cpu_id();
    if let Some(slot) = NEED_RESCHED.get(hart) {
        slot.store(true, Ordering::Release);
    }
}

/// Called from `entry/aarch64/asm/trap_entry.S`'s IRQ path, AFTER
/// `aarch64_trap_entry` returns and `sp` is back on the INTERRUPTED task's
/// own stack (never on the shared IRQ stack) — mirrors riscv64's
/// `trap_resched` in `kernel/src/trap/interrupt.rs` exactly, including where it is
/// safe to call `schedule()` from and why (see that function's doc
/// comment). Not called from the sync/svc path, nor from a nested IRQ
/// (trap_entry.S's own `91:` label) — same "ONLY ON THIS PATH" restriction
/// riscv64 documents, so an SVC or a trap-within-a-trap never pays for a
/// call and an atomic swap it can never need.
#[unsafe(no_mangle)]
pub extern "C" fn aarch64_trap_resched(frame: &mut TrapFrame) {
    // Masked-window tracer: the IRQ path's window ends when this returns
    // towards the `eret` (every path below).
    #[cfg(feature = "lat-trace")]
    let _lat_exit = crate::lat_trace::IrqExit(core::panic::Location::caller());
    // `Acquire`: pairs with kernel_main's `Release` store below, so a
    // secondary that observes `true` here also observes every write
    // kernel_main did before flipping it (task A/B already created, ready
    // queues already populated) — the same visibility gap Phase 3's
    // single-core `Relaxed` load never had to close.
    if !SCHED_LIVE.load(Ordering::Acquire) {
        return;
    }
    // IRQ taken from EL0 (never a nested one): the two pieces of task work
    // that may switch away run here, on the task's own stack, not in the IRQ
    // arm of `aarch64_trap_entry` on the IRQ stack (wave 13 integration). A
    // task parked from the IRQ stack resumes on frames the hart's next IRQs
    // have overwritten (an exit's hook that blocks, a thread-group leader's
    // wait for its members in `group_exit`).
    if frame.came_from_user() {
        // RFC-0055: a task told to stop (`SYS_TASK_KILL` force) that computes
        // without a syscall ends here — a safe point: it holds no kernel lock
        // and no console. One load when no forced stop is pending anywhere.
        if azos_sched::scheduler::forced_stop_pending() {
            azos_sched::scheduler::exit_if_forced();
        }
        // Wave 13: a Linux task computing without a syscall takes its signal
        // here (the same safe point).
        if azos_limits::LINUX_ABI && azos_sched::scheduler::signal::work_pending() {
            signal_return(frame, false);
        }
    }
    let hart = azos_sched::smp::current_cpu_id();
    let Some(slot) = NEED_RESCHED.get(hart) else { return };
    if slot.swap(false, Ordering::AcqRel) {
        PREEMPT_COUNT.fetch_add(1, Ordering::Relaxed);
        azos_sched::schedule();
    }
}

// R (wave 4) — O3.1 nested-trap probe, aarch64 side. Mirrors riscv64's
// `PROBE_IRQ_IN_SYSCALL_NR`/`probe_irq_in_syscall` (`kernel/src/trap/exception.rs`,
// F4/wave 3): a reserved syscall number the syscall arm intercepts BEFORE
// `ARCH.enable_all()` runs for real dispatch, so the probe's OWN inline
// enable is what starts the clock, same as the riscv64 version. Spins
// ~50 ms reading `now_ticks()` with IRQs enabled, across many timer ticks —
// if the aarch64 analogue of the riscv64 O3.1 bug (ELR_EL1/SPSR_EL1
// clobbered by a nested IRQ inside `trap_return`, see `R-windows.md`) is
// present, this either wedges (an `eret` into unmapped kernel text takes a
// fault the `unhandled_trap` path parks on) or corrupts another task's
// kernel stack silently; a clean return with `advanced=true` after MANY
// ticks (not just one) is evidence the window is closed, not proof by a
// single non-crash. `irq-in-syscall-probe` is the SAME feature flag
// riscv64 uses (`kernel/Cargo.toml`, arch-generic — no Cargo.toml edit
// needed here).
#[cfg(all(target_arch = "aarch64", feature = "irq-in-syscall-probe"))]
const PROBE_IRQ_IN_SYSCALL_NR: u64 = 4_000_000;

#[cfg(all(target_arch = "aarch64", feature = "irq-in-syscall-probe"))]
fn probe_irq_in_syscall() -> u64 {
    use azos_arch::{Cpu, Interrupts, ARCH};
    use azos_drv_sys::kprintln;
    ARCH.enable_all();
    let tick_before = azos_actuation::watchdog::ticks();
    let hz = azos_arch::timer::freq_hz();
    let deadline = ARCH.now_ticks() + hz / 20; // ~50 ms
    while ARCH.now_ticks() < deadline {}
    let tick_after = azos_actuation::watchdog::ticks();
    kprintln!("[IRQ-PROBE] tick_before={} tick_after={} advanced={}",
        tick_before, tick_after, tick_after > tick_before);
    0
}

/// Closes a non-IRQ exception's masked window on every return path of
/// [`aarch64_trap_entry`], when the interrupted context (`SPSR_EL1` at entry)
/// runs with IRQs unmasked. Masked-window tracer only.
#[cfg(feature = "lat-trace")]
struct LatTrapExit(u64, &'static core::panic::Location<'static>);

#[cfg(feature = "lat-trace")]
impl Drop for LatTrapExit {
    fn drop(&mut self) {
        azos_arch::lat_hook::trap_exit(self.0, self.1);
    }
}

/// Everything an EL0 `svc` that `syscall_entry_fast` did not answer needs:
/// the fork snapshot, its arguments, the out-parameter and the copy-back of
/// the extra return registers. Out of line (SYSFLOOR) so `aarch64_trap_entry`
/// does not carry the snapshot's frame on the common path.
#[inline(never)]
fn svc_dispatch(frame: &mut TrapFrame, num: u64, entry: azos_syscall::SyscallEntry) -> i64 {
    // `syscall_dispatch_checked` takes `&azos_sched::UserRegs` for
    // the ONE arm that reads it — SYS_FORK/SYS_FORK_COW's
    // register-file snapshot. On aarch64 that type is
    // `azos_arch::fork_regs::ForkRegs`, not RISC-V's
    // `[u64; 32]` (see that struct's module doc): SP_EL0, SPSR_EL1,
    // TPIDR_EL0 and the full NEON/FP file are none of them GPRs, and
    // a PREVIOUS version of this function zero-padded the 31 GPRs
    // into a bare `[u64; 32]` to satisfy a signature that used to be
    // RISC-V-shaped — silently dropping all four on every aarch64
    // fork (a child would resume with a zeroed FP/SIMD register
    // file and no TLS pointer). `TrapFrame` already carries
    // everything but `TPIDR_EL0` (never written by EL1 — see
    // `ForkRegs::tpidr_el0`'s doc — so it survives an ordinary
    // same-task syscall round trip for free, but a forked CHILD is
    // a fresh task that never ran the parent's code and needs it
    // captured explicitly here).
    //
    // **Only the fork arms read `regs`, so only they pay for it.**
    // `fpstate` is 528 bytes; copying it into a snapshot on every
    // syscall, `getpid` included, cost the aarch64 syscall floor
    // 413 → 708 instructions (`vsbench` under `-icount shift=0`,
    // 2026-09-22). Gating the copy with a `Default::default()` on the
    // other branch measured WORSE (1088): that zeroes the same 528
    // bytes. So the untaken branch hands out a reference to a
    // zero-initialised `static` instead — nothing is written per
    // call, and `built` stays an unwritten stack slot unless this is
    // a fork. `dispatch_slow` reads `regs` in exactly two arms,
    // SYS_FORK and SYS_FORK_COW (crates/core/syscall/src/dispatch.rs);
    // any new reader must be added to `wants_regs` below or it reads
    // zeroes.
    static NO_REGS: azos_sched::UserRegs = unsafe { core::mem::zeroed() };
    // RFC-0047 stage 3: a Linux task's `clone` (220) forks through the
    // same snapshot. Folded away without `LINUX_ABI`.
    let wants_regs = num == azos_abi::syscall_nr::SYS_FORK
        || num == azos_abi::syscall_nr::SYS_FORK_COW
        || (azos_limits::LINUX_ABI
            && num == azos_linux_abi::nr::CLONE
            && azos_sched::scheduler::current_is_linux());
    let built;
    let user_regs: &azos_sched::UserRegs = if wants_regs {
        let tpidr_el0: u64;
        unsafe {
            core::arch::asm!(
                "mrs {0}, TPIDR_EL0",
                out(reg) tpidr_el0,
                options(nomem, nostack, preserves_flags),
            );
        }
        built = azos_sched::UserRegs {
            gpr:       frame.regs,
            sp_el0:    frame.sp_el0,
            spsr_el1:  frame.spsr_el1,
            tpidr_el0,
            // Lazy FP: the parent's FP state is in the registers (if
            // live on this hart) or in its save area — not in `frame`.
            fpstate:   fp_lazy::snapshot_current(),
        };
        &built
    } else {
        &NO_REGS
    };

    let mut out = azos_syscall::SyscallOut::new();
    let result = azos_syscall::syscall_dispatch_checked(
        entry, num,
        frame.regs[REG_X0], frame.regs[REG_X0 + 1], frame.regs[REG_X0 + 2],
        frame.regs[REG_X0 + 3], frame.regs[REG_X0 + 4], frame.regs[REG_X0 + 5],
        frame.elr_el1, frame.sp_el0,
        user_regs,
        &mut out,
    );
    if out.written {
        frame.regs[1] = out.regs[0];
        frame.regs[2] = out.regs[1];
        frame.regs[3] = out.regs[2];
        frame.regs[4] = out.regs[3];
        frame.regs[5] = out.regs[4];
        frame.regs[6] = out.regs[5];
    }
    result
}

/// The syscall entry record (wave 15): `[nr, tid, x0, x1]` from the frame.
#[inline(never)]
fn trace_sys_enter(frame: &TrapFrame) {
    azos_trace::raw::sys_enter(frame.regs[REG_X8] as u32, azos_sched::current_task_tid(), frame.regs[REG_X0], frame.regs[REG_X0 + 1]);
}

/// The syscall exit record (wave 15): `[nr, tid, ret]` from the frame.
#[inline(never)]
fn trace_sys_exit(frame: &TrapFrame) {
    azos_trace::raw::sys_exit(frame.regs[REG_X8] as u32, azos_sched::current_task_tid(), frame.regs[REG_X0] as i64);
}

/// Entry point `entry/aarch64/asm/trap_entry.S`'s vector table jumps to
/// once it has saved the register file + system registers + FP/SIMD state
/// into a `TrapFrame` on the kernel stack (Item 2 Stage 5, then Phase 2,
/// then Phase 6 — userspace).
///
/// Handled: `svc #0` at EL1 (the self-test, unchanged from Phase 2), a
/// real `svc #0` from EL0 (Phase 6 — dispatched through the SAME
/// `crates/core/syscall` dispatcher riscv64 uses), and any IRQ (GICv3 dispatch,
/// [`handle_irq`]) — all three mutate `frame` and RETURN, and
/// `trap_entry.S` restores FP/SIMD + GPRs + `ELR_EL1`/`SPSR_EL1`/`SP_EL0`,
/// conditionally switches `TTBR0_EL1` (see the return value below), and
/// `eret`s. Everything else — page faults, illegal instructions, an
/// unarmed stray interrupt — is still a boot-path bug worth reporting
/// loudly and parking on, not recovering from (`unhandled_trap`).
///
/// **Return value**: the `TTBR0_EL1` physical address `trap_entry.S` must
/// switch to before this `eret`, or `0` to keep whatever is already
/// installed. Mirrors riscv64's `trap_handler` returning the `satp` to
/// write before `sret` (`kernel/src/entry/riscv64.rs`) — the ONLY case that is ever
/// nonzero is a `SYS_EXEC`/autorun hand-off consumed on this same syscall
/// (`take_current_task_exec_ctx`), same as RISC-V's K-C21.
#[unsafe(no_mangle)]
pub extern "C" fn aarch64_trap_entry(frame: &mut TrapFrame) -> u64 {
    // Masked-window tracer (`lat-trace`): an exception from a context with
    // `PSTATE.I` clear opens a window. The IRQ path closes it in
    // `aarch64_trap_resched`; every other class on return, through
    // `LatTrapExit` (a syscall usually closed it earlier, at `enable_all`).
    #[cfg(feature = "lat-trace")]
    let _lat_exit = {
        let spsr = frame.spsr_el1;
        if matches!(frame.class(), TrapClass::Interrupt) {
            azos_arch::lat_hook::trap_enter(spsr, core::panic::Location::caller());
            None
        } else {
            azos_arch::lat_hook::trap_enter(spsr, core::panic::Location::caller());
            Some(LatTrapExit(spsr, core::panic::Location::caller()))
        }
    };
    match frame.class() {
        TrapClass::Syscall => {
            if !frame.came_from_user() {
                // EL1 self-test (Phase 2), unchanged: a kernel-mode `svc #0`
                // is never a real syscall on this milestone — nothing at EL1
                // issues one except `kernel_main`'s own round-trip probe.
                frame.regs[REG_X0] = SELFTEST_SVC_REPLY;
                // **Do NOT advance ELR_EL1 here.** Unlike RISC-V's `ecall`
                // (where `sepc` is left pointing AT the `ecall` itself, so
                // the handler must add 4 to skip it), the ARM ARM (§D1.10,
                // "Exceptions from an SVC, HVC, or SMC instruction")
                // specifies that for SVC/HVC/SMC the PE already sets
                // ELR_ELx to the address of the instruction AFTER the SVC
                // before the exception handler ever runs. Adding 4 again —
                // as an earlier version of this function did, ported
                // straight from the RISC-V convention without checking the
                // ARM ARM — skips the instruction actually following the
                // `svc`, landing execution one instruction further into
                // whatever code happens to be there. That is exactly what
                // made `kernel_main`'s self-test read back a stale register
                // instead of `SELFTEST_SVC_REPLY`: the instruction it
                // skipped over was the one that would have copied `x0` into
                // the register the test actually reads. Real EL0 syscalls
                // below share the same non-adjustment for the same reason.
                return 0;
            }

            // Real syscall from EL0 — the milestone this function exists
            // for. Same convention riscv64's `handle_exception`'s
            // `TRAP_ECALL_FROM_U` arm uses, x8/x0..x5 in place of a7/a0..a5
            // (`crates/core/abi::syscall_nr`'s aarch64 convention, wired by
            // agent H before this task started).
            let num = frame.regs[REG_X8];

            // Owner decision O3.1 (2026-09-26): syscalls run with interrupts
            // ENABLED once the trap frame is saved (Linux model), matching
            // the riscv64 side's own `ARCH.enable_all()` right after `let
            // num = frame.regs[17]`. Nesting-safety analysis (this task's
            // report, `rfcs/wave4/R-windows.md`): `_trap_common` allocates
            // every frame relative to whatever `sp` (== `SP_EL1`) is live,
            // so a nested IRQ taken here gets its OWN frame further down
            // THIS task's own per-task kernel stack, then switches to the
            // per-hart IRQ stack for the handler body itself
            // (`trap_entry.S`'s `90:` path) — the same mechanism that
            // already handles an interrupt-inside-interrupt today, and
            // exactly what `config/Kconfig.limits`'s `KERNEL_STACK_SIZE_KB` help
            // text says the per-task budget was sized for ("the deepest
            // syscall handler chain including interrupt nesting",
            // 2026-09-16).
            //
            // **Corrected claim** (the previous version of this comment
            // said "DAIF is saved/restored via SPSR_EL1 ... no special-
            // casing needed" — false, verified wrong by reading
            // `trap_entry.S`, not by trusting the comment): `SPSR_EL1` is
            // only "the PSTATE `eret` will restore" and does NOT affect
            // this hart's OWN live `DAIF` mask. Without an explicit
            // `msr DAIFSet` in `trap_return` BEFORE it writes
            // `ELR_EL1`/`SPSR_EL1`, a real IRQ landing in that window takes
            // a nested exception that clobbers both CSRs and is never
            // restored — the riscv64 sepc-clobber bug, ported here by a
            // different mechanism. `trap_entry.S`'s `trap_return` masks
            // first; it is also the tail the exec/fork first entries
            // (`aarch64_enter_user*` below) return through.
            #[cfg(all(target_arch = "aarch64", feature = "irq-in-syscall-probe"))]
            if num == PROBE_IRQ_IN_SYSCALL_NR {
                return probe_irq_in_syscall();
            }
            {
                use azos_arch::Interrupts;
                azos_arch::ARCH.enable_all();
            }
            azos_sched::swcensus::ecall_enter();

            // SYSFLOOR: the filter verdict and the three register-only calls
            // first (`syscall_entry_fast`); the fork snapshot, the argument
            // list and the `SyscallOut` are built only for a call that needs
            // them, out of line in `svc_dispatch`. The filter still runs
            // first for every number, exactly as inside
            // `syscall_dispatch_out`.
            // Wave 15 (TRACE): the syscall class's tracepoints, compiled out
            // (no instruction) unless Kconfig `KTRACE_CLASS_SYSCALL`; out of
            // line and reading the frame, as riscv64's (`handle_ecall`).
            if azos_trace::syscall_on() {
                trace_sys_enter(frame);
            }
            let result = match azos_syscall::syscall_entry_fast(num) {
                azos_syscall::SyscallEntry::Done(r) => r,
                entry => svc_dispatch(frame, num, entry),
            };
            frame.regs[REG_X0] = result as u64;
            if azos_trace::syscall_on() {
                trace_sys_exit(frame);
            }

            // No ELR_EL1 adjustment — see the EL1 self-test arm's comment
            // above; the ARM ARM already leaves it past the `svc`.

            // K-C21 equivalent: if THIS task ran `exec_user()` inside this
            // syscall (SYS_EXEC / autorun's direct call, consumed here the
            // same way riscv64 consumes it at the tail of its own ecall
            // arm), install the new EL0 entry point and hand the new
            // TTBR0_EL1 back for `trap_entry.S` to switch before `eret`.
            if let Some(ctx) = azos_sched::take_current_task_exec_ctx() {
                // The new image starts with zeroed FP registers, not the old
                // image's (they used to be restored from this frame).
                fp_lazy::discard_current();
                frame.elr_el1  = ctx.entry;
                frame.spsr_el1 = 0;           // EL0t, DAIF clear
                frame.sp_el0   = ctx.user_sp;
                return ctx.satp;              // switch TTBR0_EL1
            }
            // Wave 13: signal work (a Linux task's pending signal or
            // sigreturn) at this return to EL0. One load when there is none
            // anywhere; the work itself is out of line.
            if azos_limits::LINUX_ABI && azos_sched::scheduler::signal::work_pending() {
                signal_return(frame, true);
            }
            azos_sched::swcensus::ecall_exit();
            0
        }
        TrapClass::Interrupt => {
            // U01-7/U10-13 (audit): mark interrupt context on THIS ISA too.
            // `crates/core/ipc::fast_ipc` reads `azos_sync::isr_depth::in_isr`
            // to detect a lock taken from an ISR (the precondition for a
            // same-hart `FAST_IPC` deadlock — owner decision 2026-09-20,
            // "MUST stay 0") — riscv64's `handle_interrupt` has bracketed its
            // own interrupt arm with `enter`/`exit` since that decision
            // landed (`kernel/src/trap/interrupt.rs`); this arm never did, so the
            // detector was permanently blind on aarch64 and every fast-IPC
            // call there ran unmeasured against exactly the hazard the
            // decision asked to detect, not mask (for interrupt-latency
            // reasons that apply here just as much as on riscv64).
            let hart_for_isr = azos_sched::smp::current_cpu_id();
            azos_sync::isr_depth::enter(hart_for_isr);
            handle_irq(frame);
            azos_sync::isr_depth::exit(hart_for_isr);
            // The forced stop and the Linux signal taken at an interrupt
            // from EL0 are handled in `aarch64_trap_resched`, on the task's
            // own stack, not here on the IRQ stack: both can park the task.
            0
        }
        TrapClass::PageFault => { handle_page_fault(frame); 0 }
        // First FP/SIMD instruction from EL0 since this task was switched
        // in: load its FP state and let the instruction re-execute. IRQs
        // stay masked for the whole arm (never `enable_all()` here). An EC
        // 0x07 from EL1 is a kernel FP use outside the allowed save/restore
        // code and stays fatal.
        TrapClass::OtherException
            if (frame.esr_el1 >> ESR_EC_SHIFT) & ESR_EC_MASK == EC_FP_ACCESS
                && frame.came_from_user() =>
        {
            if !fp_lazy::first_use() {
                unhandled_trap(frame);
            }
            0
        }
        // A synchronous exception from EL0 that no arm above handles — an
        // undefined instruction (`udf`, EC 0x00), a misaligned SP/PC, a BRK,
        // a trapped system-register access — is the task's fault, not the
        // kernel's. riscv64 kills just that task (`kernel/src/trap/exception.rs`,
        // "Killing user task"); this ISA used to halt the whole machine,
        // motors included, for one bad user instruction. SError/FIQ and
        // anything from EL1 still take the fatal path below.
        _ if frame.vector == VEC_SYNC_LOWER_EL && frame.came_from_user() => {
            kill_user_task_on_trap(frame)
        }
        _ => unhandled_trap(frame),
    }
}

// ── First entry into EL0: the same tail as every trap return ────────────
//
// `crates/core/sched/src/process.rs`'s `sret_to_user`/`sret_to_user_forked`
// call these. Each builds an ordinary `TrapFrame` and hands it to
// `trap_entry.S`'s `trap_return` (through `aarch64_ret_to_user*`), so there
// is one EL0-return sequence in the kernel — see the comment above
// `aarch64_ret_to_user` for what it does and why the reschedule check is
// not part of it.
unsafe extern "C" {
    fn aarch64_ret_to_user(frame: *const TrapFrame, ttbr0: u64) -> !;
    fn aarch64_ret_to_user_tls(frame: *const TrapFrame, ttbr0: u64, tpidr_el0: u64) -> !;
}

/// A task's first entry into a fresh image: `entry` with `user_sp`, every
/// GPR zero, EL0t with DAIF clear, zeroed FP state. `ttbr0` = the new
/// table's PA, or 0 to keep the one installed.
///
/// # Safety
/// Same contract as `process::sret_to_user`: `entry`/`user_sp` valid for
/// the address space `ttbr0` (or the current one) describes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aarch64_enter_user(entry: u64, user_sp: u64, ttbr0: u64) -> ! {
    // The image starts with zeroed FP registers: drop any state the task
    // had (a kernel task that execs has none; a re-exec would have some).
    fp_lazy::discard_current();
    let frame = TrapFrame { elr_el1: entry, spsr_el1: 0, sp_el0: user_sp, ..TrapFrame::default() };
    unsafe { aarch64_ret_to_user(&frame, ttbr0) }
}

/// A forked child's first entry: the parent's EL0 registers from `regs`
/// (`ForkRegs`, captured at the parent's `svc`) with x0 = 0, resuming at
/// `entry`; the parent's FP state becomes the child's saved state.
///
/// # Safety
/// Same contract as `process::sret_to_user_forked`: `entry`, `ttbr0` and
/// `regs` describe the same, fully published child context.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aarch64_enter_user_forked(
    entry: u64,
    ttbr0: u64,
    regs: *const azos_sched::UserRegs,
) -> ! {
    let regs = unsafe { &*regs };
    fp_lazy::adopt(&regs.fpstate);
    let mut frame = TrapFrame {
        regs: regs.gpr,
        elr_el1: entry,
        // Verbatim, not a fixed EL0t constant: NZCV/DAIF at the instant of
        // the parent's `svc` are part of what the child clones.
        spsr_el1: regs.spsr_el1,
        sp_el0: regs.sp_el0,
        ..TrapFrame::default()
    };
    frame.regs[REG_X0] = 0; // fork() returns 0 in the child
    unsafe { aarch64_ret_to_user_tls(&frame, ttbr0, regs.tpidr_el0) }
}

/// ESR_EL1 ISS bit 6 (WnR) for a Data Abort (EC 0x24/0x25): 1 = the
/// faulting access was a write. Occupies the same absolute bit position in
/// the full register as in the ISS field (ISS is bits [24:0]).
const ESR_ISS_WNR: u64 = 1 << 6;

/// Wave 11 (LEASE2/LEASE3): name and count a user fault that touched a lease
/// mapping the kernel revoked, or a lessor's own buffer under a seal. The
/// caller kills the task. `#[inline(never)]`: `handle_page_fault` is inlined
/// into `aarch64_trap_entry`, and with this body inline there `syscall-floor`
/// read +2 instructions (vsbench, `-icount`); out of line, +0.
#[inline(never)]
fn page_fault_note_lease(fault_va: usize, show: bool) {
    let tid = azos_sched::current_task_tid();
    if let Some(lease) = azos_ipc::lease::lease_revoked_fault(tid, fault_va).filter(|_| show) {
        azos_drv_sys::kwarn!(
            "[LEASE] task {} touched lease {} mapping at {:#x} after it was revoked: recorded ({} since boot)",
            tid, lease, fault_va, azos_ipc::lease::lease_revoked_faults(),
        );
    }
    if let Some(lease) = azos_ipc::lease::lease_sealed_fault(tid, fault_va).filter(|_| show) {
        azos_drv_sys::kwarn!(
            "[LEASE] task {} wrote its buffer at {:#x} while lease {} sealed it: recorded ({} since boot)",
            tid, fault_va, lease, azos_ipc::lease::lease_seal_faults(),
        );
    }
}

/// Page-fault policy — mirrors riscv64's `TRAP_INSTR_PAGE_FAULT |
/// TRAP_LOAD_PAGE_FAULT | TRAP_STORE_PAGE_FAULT` arm in
/// `kernel/src/trap/exception.rs`'s `handle_exception` (COW break, then demand
/// paging, then kill-the-task): **a fault from EL0 kills that task, never
/// the kernel; a fault from EL1 is fatal**, and the EL1 arm now reproduces
/// riscv64's motor-stop/shutdown tail (U01-3 — the "this ISA drives no
/// actuator yet" premise this comment used to state is false:
/// `rt_motor_task`/`flight_control_task` both run on aarch64, `kernel/src/
/// main.rs`).
///
/// Not folded into `aarch64_trap_entry` itself: that function's match arms
/// are otherwise all one or two lines, and COW/demand-paging resolution
/// (each with its own early return) reads far better as its own body.
fn handle_page_fault(frame: &mut TrapFrame) {

    let from_user = frame.came_from_user();
    let write = frame.esr_el1 & ESR_ISS_WNR != 0;
    let fault_va = frame.far_el1 as usize;
    // Wave 15 (TRACE): the fault class, on every fault, resolved or not; the
    // cause is the ESR_EL1 exception class.
    if azos_trace::fault_on() {
        azos_trace::raw::page_fault(fault_va as u64, (frame.esr_el1 >> 26) as u32, azos_sched::current_task_tid());
    }

    if from_user {
        let user_pt = azos_sched::current_user_pt();
        if user_pt != 0 {
            // COW break — write faults only, same restriction riscv64's
            // own arm applies (a read of a COW page is never the reason
            // it is COW in the first place).
            if write {
                if azos_mm::vmm::handle_cow_fault(user_pt, fault_va).is_ok() {
                    azos_mm::vmm::note_cow_resolved();
                    return; // resolved, resume the task — silently
                }
            }
            // Demand paging — any access class (matches riscv64: it does
            // not gate this call on `write` either).
            if azos_mm::vmm::handle_demand_fault(user_pt, fault_va).is_ok() {
                azos_mm::vmm::note_demand_resolved();
                return; // resolved, resume the task — silently
            }
        }

        // Neither resolved it — genuinely fatal for THIS task, not the
        // kernel. This is the isolation property Phase 6's goal 4 asks
        // for: a user program touching unmapped/foreign memory loses only
        // itself.
        // Wave 11 (LEASE2/LEASE3): a touch of a revoked lease mapping, or a
        // lessor's write under a seal, is recorded and named — riscv64's
        // `page_fault_note_lease`. Out of line, with the rate-limited
        // report: this function is inlined into the trap entry every
        // syscall goes through.
        report_user_page_fault(write, fault_va, frame.elr_el1);
        azos_sched::scheduler::task_exit_by_signal(azos_abi::exit_status::KILLED_SEGV);
        // task_exit() never returns — context_switch abandons this frame.
    }

    // EL1 (kernel) fault: not recoverable on this milestone. Report and
    // park, same as any other unhandled trap class. Bypass first, so none of
    // it is parked behind a ring-3 console owner.
    azos_drv_sys::uart::console_bypass_for_halt();
    azos_drv_sys::kerr!();
    // `lr` is printed on purpose: the faulting PC is almost always inside
    // `memcpy`/`memset`, and the caller is what identifies the bug. Five of
    // the six physical-address-as-pointer faults found during the upper-half
    // migration were located this way in one boot each.
    azos_drv_sys::kerr!("[FATAL] aarch64 kernel page fault: {} at {:#x} (elr={:#x} lr={:#x})",
        if write { "write" } else { "read/exec" }, fault_va, frame.elr_el1, frame.regs[30]);
    fatal_halt();
}

/// U01-3: the ENTIRE shutdown tail every aarch64 fatal trap arm now shares —
/// matches riscv64's own kernel-fault tail (`kernel/src/trap/exception.rs`'s S-mode
/// page-fault and "all other exceptions" arms: motor stop, then a real
/// system shutdown, not a `wfi` loop this hart alone observes).
///
/// `set_panicked()` first: `domains/robot/safety-core::watchdog::halt_if_panicked`
/// runs in every hart's own timer ISR and, once the flag is visible, that
/// hart stops its own actuators and parks itself WITHOUT feeding the
/// watchdog — so any hart still running (rt-motor/flight-control tasks
/// live on this ISA, contrary to this function's old comment) is brought
/// down even if `ARCH.shutdown()` below has PSCI-implementation latency
/// before `SYSTEM_OFF` actually cuts power. `ARCH.shutdown()` (aarch64:
/// `psci::system_off()`) is `Boot::shutdown(&self) -> !`, the same trait
/// method riscv64's `sbi::shutdown()` implements — one call, both ISAs.
fn fatal_halt() -> ! {
    use azos_arch::Boot;
    azos_common::set_panicked();
    #[cfg(feature = "domain-robot")]
    azos_robot::motor_cmd_publish(0, 0);
    azos_arch::ARCH.shutdown()
}

/// Kill the current user task for a synchronous EL0 exception no arm
/// handles. Same choice as the EL0 page-fault arm above and riscv64's
/// user-exception arm: NO `motor_cmd_publish(0, 0)` — the control stack is
/// still running and did not ask for a stop.
fn kill_user_task_on_trap(frame: &mut TrapFrame) -> ! {
    // NOT "unhandled": gate rows read "[AARCH64-TRAP] unhandled" as the
    // machine going down, and this path is the machine staying up. The
    // report is rate limited (`user_fault_report`); the kill is not.
    if user_fault_report() {
        print_trap(frame, "user fault");
        azos_drv_sys::kwarn!("[AARCH64-TRAP] Killing user task '{}' (tid {})",
            azos_sched::current_task_name(),
            azos_sched::current_task_tid());
    }
    // ESR_EL1.EC → the status `waitpid` reports (128 + signal), not 0.
    use azos_abi::exit_status as es;
    let code = match (frame.esr_el1 >> ESR_EC_SHIFT) & ESR_EC_MASK {
        0x22 | 0x26 => es::KILLED_BUS,   // PC / SP alignment
        0x3C => es::KILLED_TRAP,         // BRK
        _ => es::KILLED_ILL,             // 0x00 unknown (`udf`), trapped sysreg, rest
    };
    azos_sched::scheduler::task_exit_by_signal(code);
    // task_exit() never returns — context_switch abandons this frame.
}

/// riscv64's `user_fault_report` (kernel/src/trap/exception.rs): console
/// reports of user tasks killed by a fault, 10 per 5 s, then a count of
/// those dropped. The kill, the exit status and the lease records are not
/// limited.
static USER_FAULT_REPORTS: azos_drv_sys::ratelimit::RateLimit =
    azos_drv_sys::ratelimit::RateLimit::new(10, 5);

#[inline(never)]
fn user_fault_report() -> bool {
    match USER_FAULT_REPORTS.check() {
        Some(0) => true,
        Some(k) => {
            azos_drv_sys::kwarn!("[FAULT] {} user-task fault report(s) suppressed", k);
            true
        }
        None => false,
    }
}

/// The EL0 page-fault report (rate limited) and the lease record (always).
#[inline(never)]
fn report_user_page_fault(write: bool, fault_va: usize, elr: u64) {
    let show = user_fault_report();
    if show {
        azos_drv_sys::kwarn!();
        azos_drv_sys::kwarn!("[PAGE FAULT] {} at {:#x} (elr={:#x}, tid={})",
            if write { "write" } else { "read/exec" }, fault_va,
            elr, azos_sched::current_task_tid());
    }
    page_fault_note_lease(fault_va, show);
    if show {
        azos_drv_sys::kwarn!("[PAGE FAULT] Killing user task");
    }
}

fn print_trap(frame: &TrapFrame, what: &str) {
    azos_drv_sys::kwarn!();
    azos_drv_sys::kwarn!("[AARCH64-TRAP] {} — vector={:#x} class={:?}",
        what, frame.vector, frame.class());
    azos_drv_sys::kwarn!("[AARCH64-TRAP]   esr_el1:  {:#x} (ec={:#x})",
        frame.esr_el1, (frame.esr_el1 >> ESR_EC_SHIFT) & ESR_EC_MASK);
    azos_drv_sys::kwarn!("[AARCH64-TRAP]   elr_el1:  {:#x}", frame.elr_el1);
    azos_drv_sys::kwarn!("[AARCH64-TRAP]   far_el1:  {:#x}", frame.far_el1);
    azos_drv_sys::kwarn!("[AARCH64-TRAP]   spsr_el1: {:#x} (from_user={})",
        frame.spsr_el1, frame.came_from_user());
    azos_drv_sys::kwarn!("[AARCH64-TRAP]   sp_el0:   {:#x}", frame.sp_el0);
}

/// Report-and-park path — the ENTIRE trap policy before this task, and
/// still what every trap class gets that is not a synchronous EL0 fault.
fn unhandled_trap(frame: &mut TrapFrame) -> ! {
    azos_drv_sys::uart::console_bypass_for_halt();
    print_trap(frame, "unhandled trap");
    azos_drv_sys::kerr!("[AARCH64-TRAP] halting — unhandled trap class");

    // U01-3: same shutdown tail as the EL1 page-fault arm above, not a
    // one-hart `wfi` loop — see `fatal_halt`'s doc comment.
    fatal_halt();
}

/// Wave 13: deliver signals (or apply a `rt_sigreturn`) to the current task
/// at its return to EL0, from a syscall (`from_syscall`) or an interrupt.
/// Out of line and not `#[cold]` (a cold callee reshapes the hot caller).
///
/// `SPSR_EL1` keeps its EL0t mode and interrupt mask; only N, Z, C and V may
/// come from a user frame, so a sigreturn cannot enter EL1 or mask its own
/// interrupts. The FP file moves through the lazy save area.
#[inline(never)]
fn signal_return(frame: &mut TrapFrame, from_syscall: bool) {
    use azos_linux_abi::signal as sig;
    let mut gpr = [0u64; 32];
    gpr[..31].copy_from_slice(&frame.regs[..31]);
    gpr[31] = frame.sp_el0;
    let mut ctx = sig::Context { gpr, pc: frame.elr_el1, pstate: frame.spsr_el1 };
    // The frame's FP words: `fpsr | fpcr << 32`, then v0..v31 (two words
    // each). `FpState` is v0..v31, then fpsr and fpcr: the same words, the
    // status word moved. Integer copies only (the kernel is FP-free).
    let changed = azos_syscall::linux::on_return_to_user(
        &mut ctx,
        from_syscall,
        &mut |w| {
            let Some(s) = fp_lazy::snapshot_current_if_used() else { return false };
            for (i, d) in w[..65].iter_mut().enumerate() {
                let at = if i == 0 { 512 } else { (i - 1) * 8 };
                let mut b = [0u8; 8];
                b.copy_from_slice(&s.0[at..at + 8]);
                *d = u64::from_le_bytes(b);
            }
            true
        },
        &mut |w| {
            let mut s = azos_arch::fp_state::FpState::zero();
            for (i, v) in w[..65].iter().enumerate() {
                let at = if i == 0 { 512 } else { (i - 1) * 8 };
                s.0[at..at + 8].copy_from_slice(&v.to_le_bytes());
            }
            fp_lazy::discard_current();
            fp_lazy::adopt(&s);
        },
    );
    if changed {
        frame.regs[..31].copy_from_slice(&ctx.gpr[..31]);
        frame.sp_el0 = ctx.gpr[31];
        frame.elr_el1 = ctx.pc;
        frame.spsr_el1 = (frame.spsr_el1 & !sig::A64_PSTATE_USER_MASK) | (ctx.pstate & sig::A64_PSTATE_USER_MASK);
    }
}
