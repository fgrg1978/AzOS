// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! x86_64 port: the arch contract and the x86 platform (boot information,
//! ACPI, LAPIC/IOAPIC, timer, AP start, paging, mitigations). The same
//! `azos_kernel` runs on it under QEMU (PVH on microvm/q35; the Limine path
//! is built).
//!
//! Off x86_64 the platform modules are not compiled, and the contract
//! methods are `todo!()`s naming the x86 mechanism (the `on_x86!` macro below): that is
//! the facade's host-side fake ISA (`azos_arch/stub`).
//!
//! Off x86_64 it exports the contract and the ISA-private modules listed
//! below, and nothing that stands in for another ISA's (`apic`, ...; `cpu`,
//! `fork_regs`, `fp`, `mmu`, `tlb`, `trap`, `seed` and `spin` share a name
//! with riscv64's/aarch64's but not their functions). So `cargo check` of a shared crate against it (the facade's
//! `stub` feature, or a bare-metal `x86_64` target) fails exactly where that
//! crate still reaches past the contract into an ISA module, and that error
//! list is what a port must add (`tools/lint/arch_stub_check.py`).
//!
//! The same crate is the facade's host-side fake ISA (`azos_arch/stub`):
//! the method list is one list, so the port and the stub cannot drift.
//!
//! Beyond the contract, ISA-private modules: [`cpu`] (the GS-relative
//! per-CPU area, `syscall` MSRs, the boot-path instructions, the FS base, and
//! `cpu::features`: the baseline / n-probe-require `X86_*` model every ISA
//! uses), [`fp`] (FP save at switch, restore on the way to ring 3: never a
//! #NM trap), [`trap`] (`gdt` / `idt`: descriptor tables and their pure
//! encoders), [`fork_regs`], [`mmu`] (paging, PTE encoding, CR3/CR4, the
//! table walker), [`tlb`] (the CR3 publication and the IPI shootdown) and
//! [`ext`] (the mitigations, the retpoline thunk, split-lock detection).
//!
//! What an x86_64 port adds beyond these methods: `kernel/src/entry/x86_64/`
//! (boot hooks, `ArchEntry`, `TrapContext`, `boot.S`/`trap_entry.S`/
//! `context_switch.S`), `kernel/linker-x86_64.ld`, ACPI MADT next to the DTB
//! for CPU discovery, LAPIC/IOAPIC in `crates/drivers/irqchip`, and the
//! `compile_error!("x86_64: ...")` branches the shared crates carry.

pub mod cpu;
/// x86_64-only extras (`ext/`): the speculation mitigations, the retpoline
/// thunk, split-lock detection.
pub mod ext;
/// Hypervisor primitives (`ext/hv/`; Kconfig `X86_SVM` / `X86_VMX`): the probe,
/// the VMCB / NPT encoders, the exit decode and the `VMRUN` stub. A
/// top-level module (not `ext::hv`) because it builds on `crate::mmu`, which
/// `tests/host/arch-tests` includes `ext/mod.rs` without.
#[path = "ext/hv/mod.rs"]
pub mod hv;
/// This ISA's `azos_arch_api::Hypervisor` (Kconfig VIRT), reached as `azos_arch::HvImpl`.
pub use hv::HvImpl;
pub mod fork_regs;
/// FP save at a switch, restore on the way to ring 3: never a #NM trap.
pub mod fp;
pub mod mmu;
/// The Intel and AMD counters behind `Pmu` (Kconfig `X86_PMU`).
pub mod pmu;
pub mod tlb;
/// The GDT/TSS and the IDT: pure encoders and tables.
pub mod trap;
// SpinWait: PAUSE, LOCK CMPXCHG, WAITPKG UMONITOR/UMWAIT (wave 15, N2).
pub mod spin;
// RDSEED / RDRAND: the entropy pool's CPU seed source.
pub mod seed;

// The platform (front X4): boot information, ACPI, LAPIC/IOAPIC, the clock
// and timer, AP start. x86_64 only, so the host stub still exports just the
// contract; `firmware` and `irq::encode` are pure and host-tested through
// `#[path]` (tests/host/x86-platform-tests).
#[cfg(target_arch = "x86_64")]
pub mod firmware;
#[cfg(target_arch = "x86_64")]
pub mod platform_impl;
#[cfg(target_arch = "x86_64")]
pub mod irq;
#[cfg(target_arch = "x86_64")]
pub mod timer;
#[cfg(target_arch = "x86_64")]
pub mod smp;

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
// Spin-wait and CAS (wave 15, N2): the trait and its ordering type.
pub use azos_arch_api::{CasOrder, SpinWait};
// The performance counters (`ARCH.cycles()`, `.instructions()`, `.event(sel)`).
pub use azos_arch_api::Pmu;
// Ring-3 port I/O's seam, and the ports the kernel's drivers reserve
// (`ioport::reserve`, where each binds; empty off x86_64).
pub use azos_arch_api::ioport;

/// The x86_64 zero-sized singleton type (`azos_arch::ArchImpl`).
pub struct X86_64;

/// The singleton (`azos_arch::ARCH`).
pub static X86_64_ARCH: X86_64 = X86_64;

impl Cpu for X86_64 {
    /// This CPU's index: the LAPIC/x2APIC ID mapped to a dense CPU number
    /// (`CPUID.0BH`/`1FH`, or the GS-relative per-CPU slot once it exists).
    fn hart_id(&self) -> usize {
        on_x86!(cpu::percpu_id(), "x86_64: hart_id: the dense CPU id at %gs:0 (cpu::PerCpu)")
    }
    /// `hlt`, with interrupts in the state the caller left them: with them
    /// masked nothing but an NMI ends it, the panic path's final stop.
    fn wait_for_interrupt(&self) {
        on_x86!(cpu::hlt(), "x86_64: wfi: hlt (mwait where the idle governor allows)")
    }
    /// Depth 0 is [`Self::wait_for_interrupt`] (`hlt`); depth `d` is the `d`-th state of
    /// `cpu::idle::ladder()` entered by `mwait` (`mwaitx` on AMD), and a depth
    /// past the ladder, or past the cap the boot set from the model's latencies, is
    /// the deepest state allowed, never a deeper one. No
    /// ladder (a model with no table, a hypervisor without `mwait`) or `IF`
    /// clear is `hlt` at every depth. The clock is `timer::now_ticks`, in
    /// `TIMER_FREQ` ticks.
    fn cpu_idle(&self, _depth: u8) -> u64 {
        on_x86!({
            let t0 = timer::now_ticks();
            let ladder = cpu::idle::ladder();
            match ladder.pick(_depth.min(cpu::idle::depth_cap())) {
                // `mwait` is entered with `sti`, so only with `IF` set: an
                // `IF`-clear wait is `hlt`.
                Some(s) if cpu::rflags() & cpu::RFLAGS_IF != 0 => {
                    // percpu-hint: the idle task is pinned to its CPU
                    cpu::idle::enter(ladder.wait(), s.hint, cpu::percpu_area(cpu::percpu_id()) as *const u8)
                }
                _ => self.wait_for_interrupt(),
            }
            azos_arch_api::ticks_to_us(timer::now_ticks().wrapping_sub(t0), timer::TICK_HZ)
        }, "x86_64: cpu_idle: hlt, or mwait at the depth the idle governor picked")
    }
    /// `cli; hlt` forever.
    fn halt(&self) -> ! {
        on_x86!(cpu::halt_forever(), "x86_64: halt: cli; hlt loop")
    }
    /// Invariant TSC (`rdtsc`, `CPUID.80000007H:EDX[8]`), frequency from
    /// `CPUID.15H` or calibrated against the HPET/PIT.
    fn now_ticks(&self) -> u64 {
        on_x86!(timer::now_ticks(), "x86_64: now_ticks: invariant TSC via rdtsc")
    }
    /// The CPU id stored at `%gs:0`: the kernel GS base is this CPU's
    /// `cpu::PerCpu` (swapped with `IA32_KERNEL_GS_BASE` by `swapgs` on
    /// every user/kernel transition), whose first word is the id.
    fn percpu_base(&self) -> usize {
        on_x86!(cpu::percpu_id(), "x86_64: percpu_base: the CPU id at %gs:0")
    }
    /// `wrmsr IA32_GS_BASE` = CPU `_base`'s `PerCpu`, stamped with the id.
    fn set_percpu_base(&self, _base: usize) {
        on_x86!(cpu::set_percpu(_base), "x86_64: set_percpu_base: IA32_GS_BASE = &PerCpu[id]")
    }
}

impl Interrupts for X86_64 {
    /// `pushfq; cli`, returning RFLAGS.IF.
    fn disable_all(&self) -> InterruptState {
        on_x86!({
            let f = cpu::rflags();
            cpu::cli();
            InterruptState(f & cpu::RFLAGS_IF)
        }, "x86_64: disable_all: pushfq; cli -> RFLAGS.IF")
    }
    /// `sti` only if the saved RFLAGS.IF was set.
    fn restore(&self, _prev: InterruptState) {
        on_x86!(if _prev.0 & cpu::RFLAGS_IF != 0 { cpu::sti() }, "x86_64: restore: sti iff saved IF")
    }
    /// `sti`.
    fn enable_all(&self) {
        on_x86!(cpu::sti(), "x86_64: enable_all: sti")
    }
    /// RFLAGS.IF.
    fn interrupts_enabled(&self) -> bool {
        on_x86!(cpu::rflags() & cpu::RFLAGS_IF != 0, "x86_64: interrupts_enabled: pushfq, test IF")
    }
    /// LAPIC timer in TSC-deadline mode (`IA32_TSC_DEADLINE`), one-shot.
    fn set_timer_deadline(&self, _deadline_ticks: u64) {
        on_x86!(timer::set_deadline(_deadline_ticks), "x86_64: set_timer_deadline: wrmsr IA32_TSC_DEADLINE")
    }
    /// A fixed-vector IPI through the LAPIC ICR (x2APIC `wrmsr 0x830`).
    fn send_ipi(&self, _target_hart: usize) {
        on_x86!({ irq::apic::send_ipi(_target_hart, irq::encode::RESCHED_VECTOR); }, "x86_64: send_ipi: LAPIC ICR fixed vector")
    }
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
    /// No break-before-make: x86 defines no TLB conflict abort for a
    /// table-to-large-page change of the same map; `INVLPG`/the shootdown
    /// after it is what the architecture asks for.
    #[inline]
    fn block_change_needs_bbm(&self) -> bool { false }
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
    fn pte_make_marker(&self, kind: azos_arch_api::PageMarker, payload: u32) -> u64 { mmu::make_marker(kind.code(), payload) }
    #[inline]
    fn pte_marker(&self, word: u64) -> Option<(azos_arch_api::PageMarker, u32)> {
        let (code, payload) = mmu::marker_of(word)?;
        Some((azos_arch_api::PageMarker::from_code(code)?, payload))
    }
    #[inline]
    fn pte_is_demand(&self, word: u64) -> bool { mmu::is_demand(word) }
    #[inline]
    fn pte_demand_perms(&self, word: u64) -> PagePerms { mmu::demand_perms(word) }
    /// Publish, then `mov cr3, root|PCID` (no-flush clear: the incoming
    /// PCID's entries go, as every switch flushes on the other ISAs).
    fn switch_pt(&self, _root_phys: usize, _asid: u16) {
        // percpu-hint: the arch contract: the switch path and boot, interrupts off
        on_x86!(tlb::switch_root(self.hart_id(), _root_phys, _asid), "x86_64: switch_pt: mov cr3, root|PCID")
    }
    /// The kernel half lives in every root (shared upper PML4 entries); a
    /// kernel-only root is a CR3 write with PCID 0.
    fn switch_kernel_pt(&self, _root_phys: usize) {
        // percpu-hint: the arch contract: the switch path and boot, interrupts off
        on_x86!(tlb::switch_root(self.hart_id(), _root_phys, 0), "x86_64: switch_kernel_pt: mov cr3, PCID 0")
    }
    /// `invpcid` type 2 (globals too), else a CR4.PGE toggle.
    fn flush_tlb_all(&self) {
        on_x86!({
            // The flush and the CPU left out of the stale marks are one
            // window: the CPU that did not flush must not be the one skipped.
            let irq = self.disable_all();
            mmu::cpu::flush_all();
            // Local only: other CPUs keep retained PCIDs (Kconfig `TLB_RETAIN`).
            azos_arch_api::tlb_gen::mark_all_stale(self.hart_id());
            self.restore(irq);
        }, "x86_64: flush_tlb_all: invpcid all / CR4.PGE toggle")
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
        on_x86!({
            mmu::cpu::invlpg(_va);
            // `invlpg` drops the CURRENT PCID's entry only: every CPU, this
            // one included, may hold it under a retained PCID (`TLB_RETAIN`).
            azos_arch_api::tlb_gen::mark_all_stale(usize::MAX);
        }, "x86_64: flush_tlb_page: invlpg")
    }
    /// No broadcast invalidate on x86: an IPI to every CPU holding the root,
    /// each running `invlpg` (`tlb.rs`; Linux `flush_tlb_mm_range`).
    fn tlb_shootdown(&self, _root_phys: usize, _va: usize, _len: usize) -> usize {
        on_x86!(tlb::shootdown(_root_phys, _va, _len), "x86_64: tlb_shootdown: IPI to holders + invlpg each")
    }
    #[inline]
    fn root_holders(&self, root_phys: usize) -> usize { tlb::holders(root_phys) }
    /// The A bit, bit 5 of every paging-structure entry.
    #[inline]
    fn pte_accessed_bit(&self) -> u64 { mmu::A }
    /// Through the direct map, as `mm::addr::phys_to_virt` (identity in a host build).
    #[inline]
    fn table_word(&self, pa: usize) -> *const core::sync::atomic::AtomicU64 {
        #[cfg(target_os = "none")]
        { (pa + mmu::DIRECT_MAP_BASE as usize) as *const core::sync::atomic::AtomicU64 }
        #[cfg(not(target_os = "none"))]
        { pa as *const core::sync::atomic::AtomicU64 }
    }
    /// The CPU sets A on every walk through a leaf that has it clear; there
    /// is no mode to turn off, so a harvest never costs a fault.
    #[inline]
    fn accessed_in_hardware(&self) -> bool { true }
}

impl Boot for X86_64 {
    /// ACPI S5 from the FADT and the DSDT's `\_S5` (`firmware::power::
    /// power_off`); where it is refused (no `\_S5` the boot could read
    /// without AML, no register) or does not take, the CPU stops with the
    /// machine on. Under QEMU with Kconfig `X86_QEMU_DEBUG_EXIT`, first
    /// isa-debug-exit (status 1): the gate's rows read that status.
    fn shutdown(&self) -> ! {
        on_x86!({
            cpu::cli();
            cpu::qemu_debug_exit(0);
            let _ = firmware::power::power_off(platform_impl::platform().acpi.fadt.as_ref(), &mut platform_impl::HwPower);
            cpu::halt_forever()
        }, "x86_64: shutdown: ACPI S5 via FADT PM1a_CNT")
    }
    /// The reset ladder (`firmware::power::reset`): FADT `RESET_REG`, port
    /// 0xCF9, the 8042, then a triple fault. Under QEMU with Kconfig
    /// `X86_QEMU_DEBUG_EXIT`, first isa-debug-exit (status 5).
    fn reboot(&self) -> ! {
        on_x86!({
            cpu::cli();
            cpu::qemu_debug_exit(2);
            firmware::power::reset(platform_impl::platform().acpi.fadt.as_ref(), &mut platform_impl::HwPower);
            cpu::triple_fault()
        }, "x86_64: reboot: FADT RESET_REG / port 0xCF9")
    }
    /// INIT-SIPI-SIPI through the LAPIC ICR to the APIC ID from the MADT,
    /// with a real-mode trampoline below 1 MiB (`kernel/src/entry/x86_64/asm/boot.S`).
    fn hart_start(&self, _hart_id: usize, _start_pc: usize, _opaque: usize) -> Result<(), HartStartError> {
        on_x86!(smp::hart_start(_hart_id, _start_pc, _opaque), "x86_64: hart_start: INIT-SIPI-SIPI to the MADT APIC ID")
    }
}

impl Vector for X86_64 {
    /// SSE2 is baseline on x86_64; AVX2 only behind `features::detect().avx2`
    /// (Kconfig `X86_AVX2`), inside a kernel FPU section that saves the
    /// interrupted task's state eagerly (`fpu`).
    ///
    /// The kernel is built soft-float (`x86_64-unknown-none`), so this is the
    /// portable loop until a kernel FPU section exists.
    fn dot_f32(&self, a: &[f32], b: &[f32]) -> f32 {
        let mut acc = 0.0f32;
        for (x, y) in a.iter().zip(b.iter()) {
            acc += x * y;
        }
        acc
    }
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
    fn icache_needs_dcache_clean(&self) -> bool { false }
    unsafe fn dcache_clean(&self, _va: usize, _len: usize) {}
    /// A serializing instruction on every CPU: `cpuid` here, and on every
    /// other online CPU (each publishes its root when it joins, `tlb::join`)
    /// the shootdown IPI with an empty range (its `iretq` serializes),
    /// waited for as a shootdown is.
    fn icache_sync_all(&self) {
        on_x86!({
            let _ = platform_impl::cpuid(0, 0);
            tlb::shootdown_kernel(0, 0);
        }, "x86_64: icache_sync_all: IPI + serialize on every CPU")
    }
    /// `invlpg` locally, then an IPI shootdown to every CPU (globals too).
    fn flush_tlb_page_all(&self, _va: usize) {
        on_x86!({ tlb::shootdown_kernel(_va, PAGE_SIZE); }, "x86_64: flush_tlb_page_all: invlpg + IPI shootdown")
    }
    /// `rep stosb` (ERMS/FSRM).
    unsafe fn zero_memory(&self, _va: usize, _len: usize) {
        // SAFETY: the caller owns `[_va, _va + _len)`, mapped writable. DF is
        // clear in the kernel (the ABI; every entry path clears it).
        on_x86!(unsafe {
            core::arch::asm!("rep stosb", inout("rdi") _va => _, inout("rcx") _len => _,
                in("al") 0u8, options(nostack, preserves_flags));
        }, "x86_64: zero_memory: rep stosb")
    }
    /// RDSEED, else RDRAND, when the boot selected one (`seed::select`);
    /// nothing on the host stub, where nothing selects.
    fn cpu_seed(&self, out: &mut [u8]) -> azos_arch_api::entropy::CpuSeed {
        seed::fill(out)
    }
    /// The CR3 value: PML4 PA | PCID.
    fn user_root_word(&self, root_phys: usize, asid: u16) -> usize {
        mmu::make_cr3(root_phys, asid, mmu::pcid_on()) as usize
    }
    /// The PCID, CR3 bits 11:0.
    fn user_root_asid(&self, word: usize) -> u16 {
        (word as u64 & mmu::CR3_PCID_MASK) as u16
    }
    fn user_root_with_asid(&self, word: usize, asid: u16) -> usize {
        let w = word as u64 & !(mmu::CR3_PCID_MASK | mmu::CR3_NOFLUSH);
        (w | (asid as u64 & mmu::CR3_PCID_MASK)) as usize
    }
    /// The PML4 frame number (CR3 bits 51:12), what `tlb::shootdown` keys on.
    fn tlb_space_key(&self, word: usize) -> usize {
        mmu::cr3_root(word as u64) >> 12
    }
    /// `invpcid` all contexts, else a CR4.PGE toggle: every PCID.
    fn flush_tlb_all_contexts_local(&self) {
        on_x86!(mmu::cpu::flush_all(), "x86_64: flush_tlb_all_contexts_local")
    }
    /// `AZOS_HART_CR3[cpu]` (`tlb::publish`), what `tlb::shootdown` scans.
    fn publish_user_root(&self, _word: usize) {
        // percpu-hint: the arch contract: the switch and exec paths, interrupts off
        on_x86!(tlb::publish(self.hart_id(), _word & !(mmu::CR3_NOFLUSH as usize)), "x86_64: publish_user_root")
    }
    /// Publish, then `mov cr3`.
    fn install_user_root_local(&self, _word: usize) {
        on_x86!({
            // percpu-hint: the arch contract: the switch and exec paths, interrupts off
            tlb::install_word(self.hart_id(), _word as u64);
            // Outside the generation scheme: the next user switch flushes.
            azos_arch_api::tlb_gen::mark_stale(self.hart_id());
        }, "x86_64: install_user_root_local: mov cr3")
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
