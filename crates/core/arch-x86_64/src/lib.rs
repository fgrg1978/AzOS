// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! x86_64 port skeleton: the arch contract, every method a `todo!()` that
//! names the x86 mechanism it stands for. Structure only — no instruction
//! here has run, and nothing builds this crate by default.
//!
//! It exports the contract and the ported modules listed below, nothing
//! else. So `cargo check` of a shared crate against it (the facade's
//! `stub` feature, or a bare-metal `x86_64` target) fails exactly where that
//! crate still reaches past the contract into an ISA module, and that error
//! list is what a port must add (`tools/arch_stub_check.py`).
//!
//! The same crate is the facade's host-side fake ISA (`azos_arch/stub`):
//! the method list is one list, so the skeleton and the stub cannot drift.
//!
//! Beyond the contract, ISA-private modules: [`features`] (the
//! baseline / n-probe-require `X86_*` model every ISA uses), [`fpu`]
//! (EAGER FP save: x86 never switches FP lazily), [`mmu`] (paging, PTE
//! encoding, CR3/CR4, the table walker) and [`tlb`] (the CR3 publication
//! and the IPI shootdown), the last two under the same names as riscv64's.
//!
//! What an x86_64 port adds beyond these methods: `kernel/src/entry/x86_64/`
//! (boot hooks, `ArchEntry`, `TrapContext`, `boot.S`/`trap_entry.S`/
//! `context_switch.S`), `kernel/linker-x86_64.ld`, ACPI MADT next to the DTB
//! for CPU discovery, LAPIC/IOAPIC in `crates/drivers/irqchip`, and the
//! `compile_error!("x86_64: ...")` branches the shared crates carry.

pub mod features;
pub mod fpu;
pub mod hw;
pub mod mmu;
pub mod tlb;

/// The x86 body on x86_64; on the host (this crate is also the facade's fake
/// ISA) the `todo!()` naming it.
macro_rules! on_x86 {
    ($e:expr, $msg:literal) => {{
        #[cfg(target_arch = "x86_64")]
        {
            $e
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            todo!($msg)
        }
    }};
}

pub use azos_arch_api::{
    ArchEntry, ArchPlatform, FirmwareMemory, Boot, Cpu, HartStartError, InterruptState, Interrupts, Mmu,
    MmuError, PagePerms, Vector, PAGE_SHIFT, PAGE_SIZE,
};

/// The x86_64 zero-sized singleton type (`azos_arch::ArchImpl`).
pub struct X86_64;

/// The singleton (`azos_arch::ARCH`).
pub static X86_64_ARCH: X86_64 = X86_64;

impl Cpu for X86_64 {
    /// This CPU's index: the LAPIC/x2APIC ID mapped to a dense CPU number
    /// (`CPUID.0BH`/`1FH`, or the GS-relative per-CPU slot once it exists).
    fn hart_id(&self) -> usize {
        on_x86!(hw::rdmsr(hw::IA32_GS_BASE) as usize, "x86_64: hart_id: x2APIC ID -> dense CPU index (per-CPU slot via GS)")
    }
    /// `sti; hlt` with interrupts in the state the caller left them.
    /// `hlt`. With interrupts masked nothing but an NMI ends it: that is a
    /// final stop (the panic path's), so it is reported through QEMU's
    /// isa-debug-exit first (status 1; a no-op without that device).
    fn wfi(&self) {
        on_x86!({
            if hw::rflags() & hw::RFLAGS_IF == 0 {
                hw::outl(hw::DEBUG_EXIT_PORT, 0);
            }
            hw::hlt()
        }, "x86_64: wfi: hlt (mwait where the idle governor allows)")
    }
    /// `cli; hlt` forever.
    fn halt(&self) -> ! {
        on_x86!(hw::halt_forever(), "x86_64: halt: cli; hlt loop")
    }
    /// Invariant TSC (`rdtsc`, `CPUID.80000007H:EDX[8]`), frequency from
    /// `CPUID.15H` or calibrated against the HPET/PIT.
    fn now_ticks(&self) -> u64 {
        on_x86!(hw::rdtsc(), "x86_64: now_ticks: invariant TSC via rdtsc")
    }
    /// `IA32_GS_BASE` (`rdgsbase`), swapped with `IA32_KERNEL_GS_BASE` by
    /// `swapgs` on every user/kernel transition.
    fn percpu_base(&self) -> usize {
        on_x86!(hw::rdmsr(hw::IA32_GS_BASE) as usize, "x86_64: percpu_base: rdgsbase (kernel GS)")
    }
    /// `wrgsbase` / `wrmsr IA32_GS_BASE`.
    fn set_percpu_base(&self, _base: usize) {
        on_x86!(hw::wrmsr(hw::IA32_GS_BASE, _base as u64), "x86_64: set_percpu_base: wrgsbase / IA32_GS_BASE")
    }
}

impl Interrupts for X86_64 {
    /// `pushfq; cli`, returning RFLAGS.IF.
    fn disable_all(&self) -> InterruptState {
        on_x86!({
            let f = hw::rflags();
            hw::cli();
            InterruptState(f & hw::RFLAGS_IF)
        }, "x86_64: disable_all: pushfq; cli -> RFLAGS.IF")
    }
    /// `sti` only if the saved RFLAGS.IF was set.
    fn restore(&self, _prev: InterruptState) {
        on_x86!(if _prev.0 & hw::RFLAGS_IF != 0 { hw::sti() }, "x86_64: restore: sti iff saved IF")
    }
    /// `sti`.
    fn enable_all(&self) {
        on_x86!(hw::sti(), "x86_64: enable_all: sti")
    }
    /// RFLAGS.IF.
    fn interrupts_enabled(&self) -> bool {
        on_x86!(hw::rflags() & hw::RFLAGS_IF != 0, "x86_64: interrupts_enabled: pushfq, test IF")
    }
    /// LAPIC timer in TSC-deadline mode (`IA32_TSC_DEADLINE`), one-shot.
    fn set_timer_deadline(&self, _deadline_ticks: u64) { todo!("x86_64: set_timer_deadline: wrmsr IA32_TSC_DEADLINE") }
    /// A fixed-vector IPI through the LAPIC ICR (x2APIC `wrmsr 0x830`).
    fn send_ipi(&self, _target_hart: usize) { todo!("x86_64: send_ipi: LAPIC ICR fixed vector") }
}

impl Mmu for X86_64 {
    /// 4 KiB base pages (2 MiB / 1 GiB leaves at levels 1 and 2).
    const PAGE_SIZE: usize = PAGE_SIZE;
    /// 4-level paging (PML4), 5 under LA57 (boot.S's choice, Kconfig `X86_LA57`).
    #[inline]
    fn levels(&self) -> usize { mmu::levels() }
    #[inline]
    fn entries_per_table(&self) -> usize { mmu::PT_ENTRIES }
    #[inline]
    fn vpn(&self, va: usize, level: usize) -> usize { mmu::vpn(va, level) }
    #[inline]
    fn pte_empty(&self) -> u64 { mmu::empty() }
    #[inline]
    fn pte_is_valid(&self, word: u64) -> bool { mmu::is_valid(word) }
    #[inline]
    fn pte_is_table(&self, word: u64, level: usize) -> bool { mmu::is_table(word, level) }
    #[inline]
    fn pte_is_leaf(&self, word: u64, level: usize) -> bool { mmu::is_leaf(word, level) }
    #[inline]
    fn pte_phys(&self, word: u64) -> usize { mmu::phys_addr(word) }
    #[inline]
    fn pte_make_table(&self, pa: usize) -> u64 { mmu::make_table(pa) }
    #[inline]
    fn pte_make_leaf(&self, pa: usize, perms: PagePerms, level: usize) -> Result<u64, MmuError> {
        mmu::make_leaf(pa, perms, level)
    }
    #[inline]
    fn pte_perms(&self, word: u64) -> PagePerms { mmu::perms_of(word) }
    #[inline]
    fn pte_is_cow(&self, word: u64) -> bool { mmu::is_cow(word) }
    #[inline]
    fn pte_share_cow(&self, word: u64) -> u64 { mmu::share_cow(word) }
    #[inline]
    fn pte_break_cow(&self, word: u64) -> u64 { mmu::break_cow(word) }
    #[inline]
    fn pte_make_demand(&self, perms: PagePerms) -> u64 { mmu::make_demand(perms) }
    #[inline]
    fn pte_is_demand(&self, word: u64) -> bool { mmu::is_demand(word) }
    #[inline]
    fn pte_demand_perms(&self, word: u64) -> PagePerms { mmu::demand_perms(word) }
    /// Publish, then `mov cr3, root|PCID` (no-flush clear: the incoming
    /// PCID's entries go, as every switch flushes on the other ISAs).
    fn switch_pt(&self, _root_phys: usize, _asid: u16) {
        on_x86!(tlb::switch_root(self.hart_id(), _root_phys, _asid), "x86_64: switch_pt: mov cr3, root|PCID")
    }
    /// The kernel half lives in every root (shared upper PML4 entries); a
    /// kernel-only root is a CR3 write with PCID 0.
    fn switch_kernel_pt(&self, _root_phys: usize) {
        on_x86!(tlb::switch_root(self.hart_id(), _root_phys, 0), "x86_64: switch_kernel_pt: mov cr3, PCID 0")
    }
    /// `invpcid` type 2 (globals too), else a CR4.PGE toggle.
    fn flush_tlb_all(&self) {
        on_x86!(mmu::cpu::flush_all(), "x86_64: flush_tlb_all: invpcid all / CR4.PGE toggle")
    }
    /// `invpcid` type 1 (single context), else a CR3 reload of the live PCID.
    fn flush_tlb_asid(&self, _asid: u16) {
        on_x86!(mmu::cpu::flush_asid(_asid), "x86_64: flush_tlb_asid: invpcid single-context")
    }
    /// 12 with CR4.PCIDE, else 0.
    fn asid_bits(&self) -> u32 {
        if mmu::pcid_on() { mmu::PCID_BITS } else { 0 }
    }
    /// `invlpg`.
    fn flush_tlb_page(&self, _va: usize) {
        on_x86!(mmu::cpu::invlpg(_va), "x86_64: flush_tlb_page: invlpg")
    }
    /// No broadcast invalidate on x86: an IPI to every CPU holding the root,
    /// each running `invlpg` (`tlb.rs`; Linux `flush_tlb_mm_range`).
    fn tlb_shootdown(&self, _root_phys: usize, _va: usize, _len: usize) -> usize {
        on_x86!(tlb::shootdown(self.hart_id(), _root_phys, _va, _len), "x86_64: tlb_shootdown: IPI to holders + invlpg each")
    }
    #[inline]
    fn root_holders(&self, root_phys: usize) -> usize { tlb::holders(root_phys) }
}

impl Boot for X86_64 {
    /// ACPI S5 (`PM1a_CNT` SLP_TYP from the FADT/DSDT `\_S5`), or the
    /// hypervisor's exit device under QEMU (`isa-debug-exit`).
    /// Today: QEMU isa-debug-exit (status 1) if present, else stop the CPU.
    fn shutdown(&self) -> ! {
        on_x86!({
            hw::outl(hw::DEBUG_EXIT_PORT, 0);
            hw::halt_forever()
        }, "x86_64: shutdown: ACPI S5 via FADT PM1a_CNT")
    }
    /// ACPI reset register (FADT `RESET_REG`), else the 0xCF9 port.
    /// Today: QEMU isa-debug-exit (status 5) if present, else stop the CPU.
    fn reboot(&self) -> ! {
        on_x86!({
            hw::outl(hw::DEBUG_EXIT_PORT, 2);
            hw::halt_forever()
        }, "x86_64: reboot: FADT RESET_REG / port 0xCF9")
    }
    /// INIT-SIPI-SIPI through the LAPIC ICR to the APIC ID from the MADT,
    /// with a real-mode trampoline below 1 MiB (`kernel/src/entry/x86_64/asm/boot.S`).
    fn hart_start(&self, _hart_id: usize, _start_pc: usize, _opaque: usize) -> Result<(), HartStartError> {
        todo!("x86_64: hart_start: INIT-SIPI-SIPI to the MADT APIC ID")
    }
}

impl Vector for X86_64 {
    /// SSE2 is baseline on x86_64; AVX2 only behind `features::detect().avx2`
    /// (Kconfig `X86_AVX2`), inside a kernel FPU section that saves the
    /// interrupted task's state eagerly (`fpu`).
    fn dot_f32(&self, _a: &[f32], _b: &[f32]) -> f32 { todo!("x86_64: dot_f32: SSE2 / AVX2 under kernel_fpu_begin") }
    fn is_accelerated(&self) -> bool { todo!("x86_64: is_accelerated") }
}

/// The user-access window: `stac` on open, `clac` on drop, both only with
/// CR4.SMAP set (they are #UD on a CPU without SMAP).
pub struct UserAccess;

impl Drop for UserAccess {
    #[inline]
    fn drop(&mut self) {
        #[cfg(target_arch = "x86_64")]
        if mmu::smap_on() {
            mmu::cpu::clac();
        }
    }
}

impl ArchPlatform for X86_64 {
    /// x86 instruction fetch snoops the data cache (self-modifying code is
    /// coherent after a serializing instruction): no clean needed.
    fn icache_needs_dcache_clean(&self) -> bool { todo!("x86_64: icache_needs_dcache_clean: false (coherent I/D)") }
    unsafe fn dcache_clean(&self, _va: usize, _len: usize) { todo!("x86_64: dcache_clean: no-op (coherent)") }
    /// A serializing instruction on every CPU (`cpuid`/`serialize`), by IPI.
    fn icache_sync_all(&self) { todo!("x86_64: icache_sync_all: IPI + serialize on every CPU") }
    /// `invlpg` locally, then an IPI shootdown to every CPU (globals too).
    fn flush_tlb_page_all(&self, _va: usize) {
        on_x86!({ tlb::shootdown_kernel(self.hart_id(), _va, PAGE_SIZE); }, "x86_64: flush_tlb_page_all: invlpg + IPI shootdown")
    }
    /// `rep stosb` (ERMS/FSRM).
    unsafe fn zero_memory(&self, _va: usize, _len: usize) { todo!("x86_64: zero_memory: rep stosb") }
    /// The CR3 value: PML4 PA | PCID.
    fn user_root_word(&self, root_phys: usize, asid: u16) -> usize {
        mmu::make_cr3(root_phys, asid, mmu::pcid_on()) as usize
    }
    /// Publish, then `mov cr3`.
    fn install_user_root_local(&self, _word: usize) {
        on_x86!(tlb::install_word(self.hart_id(), _word as u64), "x86_64: install_user_root_local: mov cr3")
    }
    type UserAccess = UserAccess;
    /// `stac` (SMAP), `clac` when the value drops.
    #[inline]
    fn user_access(&self) -> UserAccess {
        #[cfg(target_arch = "x86_64")]
        if mmu::smap_on() {
            mmu::cpu::stac();
        }
        UserAccess
    }
}
