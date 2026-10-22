// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 entry — defines the kernel-side TrapFrame layout
//! that aarch64-native trap-vector asm will populate, the early MMU bring-up
//! `boot.S` calls, and the per-core boot state; `trap.rs` handles the traps.
//!
//! The asm (VBAR_EL1 vector table, save x0..x30 + SPSR_EL1 +
//! ELR_EL1 + FAR_EL1 + ESR_EL1) lives in `arch_aarch64::mmu::boot`
//! today as a demo trampoline; once Stage 5 wires this entry
//! module into the real kernel boot path, the same asm will
//! drop into [`trap_entry`] with `&mut TrapFrame`.

#![cfg(target_arch = "aarch64")]

// BOARD_RPI5 is selectable in `make config` so the target and its notes
// live with the other boards, but nothing below drives it yet.
#[cfg(feature = "rpi5")]
compile_error!("Raspberry Pi 5 is not ported: it needs the BCM2712 PL011 debug UART as console, \
firmware boot (kernel8.img) and an EL2 entry that survives a GICv2 machine; see BOARD_RPI5's help");


pub(crate) mod board_map;
pub(crate) mod ext;
pub(crate) mod irq;
pub mod fp;
pub(crate) mod resume;
pub(crate) mod smp;
pub(crate) mod trap;

// Through the facade, same convention `aarch64_early_mmu_init` below
// already uses for `mmu::setup` — see that function's comment for why this
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
/// `azos_arch_aarch64::mmu::setup::enable_identity_map` (single source
/// for the MAIR/TCR encoding; nothing here re-derives it). This is deliberately a BOOTSTRAP mapping, not the
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
    use azos_arch::mmu::setup::{enable_identity_map, IdentityMapConfig, PageTable};

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
    if !azos_arch::mmu::setup::granule_supported() {
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
    // the lazy-FP resting state (`fp`'s module doc). Runs on every hart:
    // boot.S calls this function on the primary and on each secondary.
    let cpacr = fp::set_resting_state();
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

/// Virtual KASLR (Kconfig `KASLR`; `boot.S` calls it only when the policy is
/// not `n`), once, right after `aarch64_early_mmu_init`: pick the image base,
/// apply the image's relative relocations, record the base for
/// [`aarch64_early_ttbr1_alias`] and for `boot.S`'s jump to the upper half.
/// All the arguments are physical addresses `boot.S` took with `adrp` (the PC
/// is still low): the image (`_start`, `_kernel_end`), its relocation table
/// (`__rela_start`, `__rela_end`) and the device tree the loader passed (0 =
/// none). A `require` that cannot be met, or a table the walk rejects, prints
/// on the PL011 and stops: no console exists yet.
///
/// Runs before the relocations are applied, so it reads no pointer-bearing
/// word: see `azos_arch::mmu::kaslr_boot`.
#[unsafe(no_mangle)]
pub extern "C" fn aarch64_early_kaslr(dtb: u64, img: u64, img_end: u64, rela: u64, rela_end: u64) {
    /// The DRAM gigabyte the early identity map covers (`aarch64_early_mmu_init`):
    /// the device tree is read only if it lies inside.
    const RAM_BASE: u64 = 0x4000_0000;
    const WINDOW: u64 = 1 << 30;
    let dtb_bytes = if dtb >= RAM_BASE && dtb < RAM_BASE + WINDOW { (RAM_BASE + WINDOW - dtb) as usize } else { 0 };
    // SAFETY: boot CPU, EL1, identity map live, before any relocation and the
    // jump to the upper half (this function's only caller, `boot.S`).
    if let Err(f) = unsafe { azos_arch::mmu::kaslr_boot::boot(dtb, dtb_bytes, img, img_end, rela, rela_end) } {
        early_halt(f.text());
    }
}

/// Called from `boot.S`, once, right after `aarch64_early_mmu_init` — the
/// aarch64 parity program's TTBR1 migration, first wave. Builds a
/// STANDALONE alias table (own L1/L2/L3, separate from
/// `aarch64_early_mmu_init`'s bootstrap identity map and from
/// `crates/core/mm::vmm`'s real kernel table) mapping the same RAM window at
/// `base_pa | KERNEL_VA_OFFSET`, installs it into `TTBR1_EL1`, and turns
/// on TTBR1 walks. See `azos_arch::mmu::setup::enable_ttbr1_alias`'s
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
pub extern "C" fn aarch64_early_ttbr1_alias(img: u64, img_end: u64) {
    use azos_arch::mmu::kaslr;
    use azos_arch::mmu::setup::{enable_ttbr1_alias, ImageAlias, PageTable, Ttbr1AliasConfig};

    const RAM_BASE: u64 = 0x4000_0000;

    static mut L1: PageTable = PageTable::zero();
    static mut L2: PageTable = PageTable::zero();
    static mut L3: PageTable = PageTable::zero();
    // The slid image's own level-2 table (Kconfig KASLR; unreferenced, so
    // dropped by the linker, where the image does not slide).
    static mut L2_IMG: PageTable = PageTable::zero();

    // Where `aarch64_early_kaslr` put the image: the blocks that map it.
    // `img`/`img_end` are the physical addresses `boot.S` passes (`_start`,
    // `_kernel_end`).
    let image = if kaslr::image_slid() {
        let image_va = img.wrapping_add(kaslr::image_bias());
        let (va_block, pa_block, blocks) = azos_arch_api::kaslr::image_blocks(&kaslr::LAYOUT, image_va, img, img_end - img);
        Some(ImageAlias { l2: &raw mut L2_IMG, va_block, pa_block, blocks })
    } else {
        None
    };

    unsafe {
        enable_ttbr1_alias(Ttbr1AliasConfig {
            l1: &raw mut L1,
            l2: &raw mut L2,
            l3: &raw mut L3,
            base_pa: RAM_BASE,
            image,
        });
    }
    // `enable_ttbr1_alias` publishes `azos_arch::mmu::setup::
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
/// `azos_arch::mmu::setup::TTBR1_BOOT_VALUE`, the early-boot alias
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
    // change between the alias and the real table (`enable_paging`'s
    // `switch_kernel_pt` writes only `TTBR1_EL1`, `crates/core/arch-aarch64::
    // api_impl::Mmu::switch_kernel_pt`). The one later change is E0PD1
    // (Kconfig A64_E0PD, `boot_hooks::cpu_features`), which re-publishes
    // `TCR_BOOT_VALUE` before any secondary starts, so it still describes
    // the live register; only the TTBR1 base address needs the
    // post-`enable_paging` value.
    let ttbr1 = match SECONDARY_TTBR1_PA.load(Ordering::Acquire) {
        0 => azos_arch::mmu::setup::TTBR1_BOOT_VALUE.load(Ordering::Acquire),
        pa => pa as u64,
    };
    let tcr = azos_arch::mmu::setup::TCR_BOOT_VALUE.load(Ordering::Acquire);
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
        azos_arch::mmu::setup::enable_kernel_map(ttbr0_pa);
    }
    // `enable_kernel_map` grants EL0 FP again; back to the lazy-FP resting
    // state (see `aarch64_early_mmu_init`).
    let cpacr = fp::set_resting_state();
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
/// scalar fields are 296 bytes; `syscall_tag` brings that to 304. AArch64 faults on
/// a misaligned SP at EL1 (`EC=0x26`), so a trap entry doing `sub sp, sp,
/// #size_of::<TrapFrame>()` with a non-16-multiple would take an alignment
/// exception on its way into the handler that exists to report exceptions —
/// this is why the asserts below exist, not just the padding.
///
/// **No FP/SIMD state.** The kernel is soft-float and never touches
/// V0-V31/FPSR/FPCR, so a trap leaves the interrupted user's FP registers
/// in the hardware untouched; they are saved lazily, only when another task
/// needs the registers (`fp`'s module doc). The frame used to carry the
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
    /// Chain E commit 8 (Kconfig `SYSCALL_LEAN_ENTRY`): written once, in the
    /// frame a task first enters EL0 through ([`aarch64_enter_user`],
    /// [`aarch64_enter_user_forked`]), and by no trap: [`SYSCALL_TAG_NATIVE`]
    /// for a native task, 0 for a Linux one. Every later trap from EL0
    /// builds its frame at that same address, so `trap_entry.S`'s
    /// `_slot_sync_lower64` takes an `svc` whose EC equals it on the native
    /// path. Also keeps the frame a multiple of 16 bytes.
    pub syscall_tag: u64,
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

/// The frame tag of a native task ([`TrapFrame::syscall_tag`]): `ESR_EL1.EC`
/// of an `svc` from AArch64 state, so only a native task's syscall matches.
pub const SYSCALL_TAG_NATIVE: u64 = 0x15;

/// The tag for the frame the current task enters EL0 through.
fn user_frame_tag() -> u64 {
    if azos_sched::scheduler::current_is_foreign() { 0 } else { SYSCALL_TAG_NATIVE }
}

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
    azos_arch::irq::gic::PPI_EL1_PHYS_TIMER
} else {
    azos_arch::irq::gic::PPI_VIRT_TIMER
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
/// (`azos_arch::mmu::setup::TTBR1_BOOT_VALUE`, see that static's own doc)
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
/// online with its MPIDR" marker. A wrong `TPIDR_EL1` does not change what
/// `MPIDR_EL1` itself reads, so this array says nothing about canary (b)
/// (boot.S's secondary `TPIDR_EL1` write dropped); see `CORE_HART_ID`.
pub static CORE_MPIDR: [AtomicU64; crate::MAX_HARTS] =
    [const { AtomicU64::new(0) }; crate::MAX_HARTS];

/// This core's OWN read-back of `current_cpu_id()` (i.e. `TPIDR_EL1`),
/// published alongside [`CORE_MPIDR`]. The boot CPU's readback loop reports
/// `FAILED:` when `CORE_HART_ID[h] != h`. It is read after `secondary_main`
/// rewrites `TPIDR_EL1` (`set_percpu_base`), so canary (b) — boot.S's
/// secondary `TPIDR_EL1` write dropped — passes it; that canary fails
/// through [`CORE_TTBR0`]/[`CORE_TTBR1`] and the CPACR_EL1 readback, which
/// the earlier boot code publishes into hart 0's slot (measured, `-smp 4`).
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

/// LPI receipts, indexed by `intid - azos_arch::irq::gic::LPI_INTID_BASE`
/// (i.e. the ITS EventID an MSI-X vector was mapped to via
/// `azos_arch::irq::its::ItsDriver::map_vector`) — the acceptance-test
/// counter for the MSI-X delivery check: "per-vector count printed and shown to
/// move" reads this, and the canary (unmap the device in the ITS, or skip
/// `MAPTI`) is exactly "this array stays all-zero forever" because
/// `handle_irq` below only ever increments a slot an actual LPI arrived
/// for. Sized to `azos_arch::irq::its::MAX_EVENTS_PER_DEVICE` — stage 1a's
/// one collection/one device scope (see that module's doc); a caller
/// indexing past it is a driver bug, not a hardware event, so this bumps
/// nothing rather than panicking on an out-of-range EventID.
pub static LPI_VECTOR_COUNT: [AtomicU64; azos_arch::irq::its::MAX_EVENTS_PER_DEVICE] =
    [const { AtomicU64::new(0) }; azos_arch::irq::its::MAX_EVENTS_PER_DEVICE];

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
