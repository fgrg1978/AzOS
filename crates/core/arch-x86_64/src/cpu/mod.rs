// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 per-CPU state reached through GS, and the instructions that load
//! the CPU's descriptor tables and arm `syscall`.
//!
//! **GS holds a pointer, the contract wants an id.** `Cpu::percpu_base`
//! returns the CPU id (`azos_percpu` indexes every per-CPU table with it,
//! as on riscv64 `tp` and aarch64 `TPIDR_EL1`). On x86_64 the kernel GS base
//! is the address of this CPU's [`PerCpu`], whose first word is the id: the
//! id is one `mov %gs:0` (no `rdmsr`), and `syscall_entry` reaches its
//! scratch slots and kernel stack through the same base before it has a
//! single free register.
//!
//! `swapgs` exchanges the kernel GS base with `IA32_KERNEL_GS_BASE` (the
//! user's) on every ring-3 <-> ring-0 transition; the trap entry decides
//! whether to swap from the saved CS, never from the current GS value.
//!
//! The [`PerCpu`] array itself is the kernel's (`X86_64_PERCPU`, sized by
//! Kconfig `NR_CPUS`, `kernel/src/entry/x86_64/ext/cpu_init.rs`): this crate only
//! names its layout, and the offsets the asm uses are injected from
//! `offset_of!` here, never copied by hand.
//!
//! [`features`] is what CPUID says this CPU implements; [`idle`] is the
//! C-state ladder `Cpu::cpu_idle(depth)` enters; [`pstate`] is what the PC
//! offers for moving its clock and measuring its energy. The boot-path
//! instructions (MSRs, TSC, RFLAGS, port I/O) and the FS base arithmetic of
//! a context switch are at the end.

/// What this CPU implements, from CPUID, in the three tiers every ISA uses.
pub mod features;

/// The `MWAIT`/`MWAITX` C-state ladder behind `Cpu::cpu_idle(depth)`.
pub mod idle;

/// Hardware control-flow integrity: CET indirect-branch tracking on.
pub mod cfi;

/// What the PC can do about its clock and energy (HWP, CPPC, RAPL): the
/// probe behind the thermal framework's level request and meter.
pub mod pstate;

use crate::trap::gdt::{Tss, GDT_ENTRIES};

/// One CPU's GS-relative area.
#[repr(C, align(64))]
pub struct PerCpu {
    /// This CPU's id (the contract's per-CPU base). Offset 0: `mov %gs:0`.
    pub cpu_id: u64,
    /// The area's own address, so code holding only GS can form a pointer.
    pub self_ptr: u64,
    /// Top of the running task's kernel stack: `syscall_entry` switches to
    /// it. Written on every return to ring 3 together with TSS.RSP0.
    pub kernel_rsp: u64,
    /// `syscall_entry`'s scratch slot for the user RSP.
    pub user_rsp: u64,
    /// The FP area whose state is live in this CPU's registers, 0 when
    /// none (`kernel/src/entry/x86_64/fp.rs`).
    pub fp_live: u64,
    /// Words reserved for the entry path (keeps `gdt` 64-byte aligned).
    /// The CR3 word a CPU runs on is published in `tlb::AZOS_HART_CR3`,
    /// the array the shootdown scans, not here.
    pub _reserved: [u64; 3],
    /// This CPU's GDT (its TSS descriptor names this CPU's `tss`).
    pub gdt: [u64; GDT_ENTRIES],
    /// This CPU's TSS.
    pub tss: Tss,
}

impl PerCpu {
    /// An area before `init`: every field zero, an I/O-bitmap-less TSS.
    pub const fn new() -> Self {
        PerCpu {
            cpu_id: 0,
            self_ptr: 0,
            kernel_rsp: 0,
            user_rsp: 0,
            fp_live: 0,
            _reserved: [0; 3],
            gdt: [0; GDT_ENTRIES],
            tss: Tss::new(),
        }
    }
}

impl Default for PerCpu {
    fn default() -> Self {
        Self::new()
    }
}

/// Offsets the asm reads through `%gs:` (injected by `kernel/src/main.rs`).
pub const PERCPU_CPU_ID: usize = core::mem::offset_of!(PerCpu, cpu_id);
pub const PERCPU_KERNEL_RSP: usize = core::mem::offset_of!(PerCpu, kernel_rsp);
pub const PERCPU_USER_RSP: usize = core::mem::offset_of!(PerCpu, user_rsp);
pub const PERCPU_FP_LIVE: usize = core::mem::offset_of!(PerCpu, fp_live);
/// TSS.RSP0, as a GS offset.
pub const PERCPU_TSS_RSP0: usize = core::mem::offset_of!(PerCpu, tss) + crate::trap::gdt::TSS_RSP0;

const _: () = assert!(PERCPU_CPU_ID == 0, "hart_id is `mov %gs:0`");
const _: () = assert!(core::mem::offset_of!(PerCpu, gdt) % 8 == 0);

// ── MSRs ───────────────────────────────────────────────────────────────────
pub const IA32_EFER: u32 = 0xC000_0080;
pub const IA32_STAR: u32 = 0xC000_0081;
pub const IA32_LSTAR: u32 = 0xC000_0082;
pub const IA32_FMASK: u32 = 0xC000_0084;
pub const IA32_FS_BASE: u32 = 0xC000_0100;
pub const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// EFER.SCE: `syscall`/`sysret` enabled.
pub const EFER_SCE: u64 = 1 << 0;

// RFLAGS bits.
/// RFLAGS.IF.
pub const RFLAGS_IF: u64 = 1 << 9;
pub const RFLAGS_TF: u64 = 1 << 8;
pub const RFLAGS_DF: u64 = 1 << 10;
pub const RFLAGS_IOPL: u64 = 3 << 12;
pub const RFLAGS_NT: u64 = 1 << 14;
pub const RFLAGS_RF: u64 = 1 << 16;
pub const RFLAGS_AC: u64 = 1 << 18;
/// Bit 1 of RFLAGS reads as 1.
pub const RFLAGS_FIXED: u64 = 1 << 1;

/// `IA32_FMASK`: RFLAGS bits `syscall` clears. IF so the entry runs masked
/// until the frame is saved; TF so a single-stepping user cannot trap the
/// kernel's first instruction; DF for the C ABI; AC so ring 3 cannot open
/// the SMAP window for the kernel; NT/IOPL/RF so none leaks into ring 0.
pub const SYSCALL_RFLAGS_MASK: u64 =
    RFLAGS_IF | RFLAGS_TF | RFLAGS_DF | RFLAGS_IOPL | RFLAGS_NT | RFLAGS_RF | RFLAGS_AC;

/// The RFLAGS a fresh ring-3 image starts with: IF set, nothing else.
pub const USER_RFLAGS_INIT: u64 = RFLAGS_IF | RFLAGS_FIXED;

/// True if `va` is canonical for 48-bit virtual addresses (bits 63:47 all
/// equal). `sysretq` to a non-canonical RIP faults in ring 0 on Intel with
/// the USER RSP already loaded (CVE-2012-0217), so the return path takes
/// `iretq` instead for any RIP this rejects.
pub const fn is_canonical_user(va: u64) -> bool {
    va < (1 << 47)
}

// ── Instructions (x86_64 only) ─────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    /// The kernel's per-CPU array (element 0; `NR_CPUS` of them).
    static X86_64_PERCPU: PerCpu;
}

/// This CPU's id: `mov %gs:0`.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn percpu_id() -> usize {
    let id: usize;
    // SAFETY: the kernel GS base is this CPU's `PerCpu` from boot.S on
    // (and in the kernel half of every swapgs pair); its first word is the id.
    unsafe {
        core::arch::asm!("mov {}, qword ptr gs:[0]", out(reg) id,
            options(nostack, readonly, preserves_flags));
    }
    id
}

/// The address of CPU `id`'s area.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn percpu_area(id: usize) -> *mut PerCpu {
    // SAFETY: only the address is formed; the array has NR_CPUS elements
    // and callers pass a CPU id below it.
    unsafe { ((&raw const X86_64_PERCPU) as *mut PerCpu).add(id) }
}

/// Point this CPU's kernel GS base at CPU `id`'s area and stamp the id.
#[cfg(target_arch = "x86_64")]
pub fn set_percpu(id: usize) {
    let area = percpu_area(id);
    // SAFETY: the area belongs to the calling CPU (boot and secondary
    // bring-up, before anything else reads it here); plain stores.
    unsafe {
        (&raw mut (*area).cpu_id).write_volatile(id as u64);
        (&raw mut (*area).self_ptr).write_volatile(area as u64);
    }
    wrmsr(IA32_GS_BASE, area as u64);
}

/// `lgdt` this table, reload CS (far return) and the data selectors, then
/// `ltr`. FS and GS are not reloaded: a selector load would reset their
/// bases (vendor-dependent), and boot.S left both null.
///
/// # Safety
/// `gdt` must stay mapped and unchanged for as long as the CPU runs, and
/// must have this module's layout ([`crate::trap::gdt::table`]).
#[cfg(target_arch = "x86_64")]
pub unsafe fn load_gdt_and_tss(gdt: *const [u64; GDT_ENTRIES]) {
    use crate::trap::gdt::{DescriptorPointer, KERNEL_CS, KERNEL_DS, TSS_SEL};
    let ptr = DescriptorPointer { limit: (core::mem::size_of::<[u64; GDT_ENTRIES]>() - 1) as u16, base: gdt as u64 };
    // SAFETY: per the caller; the far return reloads CS with the same
    // kernel code selector boot.S used, so execution continues here.
    unsafe {
        core::arch::asm!(
            "lgdt [{ptr}]",
            "push {cs}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            "mov ds, {ds:x}",
            "mov es, {ds:x}",
            "mov ss, {ds:x}",
            "ltr {tss:x}",
            ptr = in(reg) &ptr,
            cs = in(reg) KERNEL_CS as u64,
            ds = in(reg) KERNEL_DS as u64,
            tss = in(reg) TSS_SEL as u64,
            tmp = out(reg) _,
        );
    }
}

/// `lidt` a 256-entry table.
///
/// # Safety
/// `idt` must stay mapped and valid for as long as the CPU runs.
#[cfg(target_arch = "x86_64")]
pub unsafe fn load_idt(idt: *const [[u64; 2]; crate::trap::idt::VECTORS]) {
    let ptr = crate::trap::gdt::DescriptorPointer {
        limit: (core::mem::size_of::<[[u64; 2]; crate::trap::idt::VECTORS]>() - 1) as u16,
        base: idt as u64,
    };
    // SAFETY: per the caller.
    unsafe { core::arch::asm!("lidt [{}]", in(reg) &ptr, options(readonly, nostack, preserves_flags)) };
}

/// Arm `syscall`: EFER.SCE, the selectors (STAR), the entry (LSTAR), the
/// RFLAGS mask (FMASK), and a zero user GS base for the first `swapgs`.
#[cfg(target_arch = "x86_64")]
pub fn enable_syscall(entry: u64) {
    wrmsr(IA32_STAR, crate::trap::gdt::STAR);
    wrmsr(IA32_LSTAR, entry);
    wrmsr(IA32_FMASK, SYSCALL_RFLAGS_MASK);
    wrmsr(IA32_KERNEL_GS_BASE, 0);
    wrmsr(IA32_EFER, rdmsr(IA32_EFER) | EFER_SCE);
}

/// CR3: the live root word (PML4 address | PCID).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn read_cr3() -> u64 {
    let v: u64;
    // SAFETY: reading CR3 at CPL0 has no side effect.
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// CR2: the linear address of the last page fault.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn read_cr2() -> u64 {
    let v: u64;
    // SAFETY: reading CR2 at CPL0 has no side effect.
    unsafe { core::arch::asm!("mov {}, cr2", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

// ── Boot-path instructions (x86_64 only) ───────────────────────────────────
// The few instructions the boot-to-banner path needs (MSRs, the TSC, RFLAGS,
// port I/O, hlt). Off x86_64 the contract methods that use them keep their
// `todo!()`.

/// IA32_GS_BASE: the kernel GS base, the address of this CPU's `cpu::PerCpu`.
pub const IA32_GS_BASE: u32 = 0xC000_0101;
/// QEMU `isa-debug-exit` (`-device isa-debug-exit,iobase=0xf4,iosize=4`):
/// a write of `v` exits QEMU with status `(v << 1) | 1`. A QEMU device the
/// gate adds: port 0xF4 on a real PC is not this. In this crate only
/// [`qemu_debug_exit`] writes it; `kernel/src/ktest.rs` writes it in a
/// Kconfig `BOARD_QEMU` build, and the boot refusals before Rust runs
/// (`boot.S`, `ext/limine.rs`) write it to end a QEMU run.
pub const DEBUG_EXIT_PORT: u16 = 0xF4;

/// End a QEMU run with status `(v << 1) | 1` through isa-debug-exit, when
/// Kconfig `X86_QEMU_DEBUG_EXIT` built it in and the CPU says it runs under
/// a hypervisor (CPUID.1:ECX[31]): never on a real PC. Returns when there is
/// no such device (the write goes nowhere), and the caller goes on to the
/// machine's own power-off or reset.
#[cfg(target_arch = "x86_64")]
pub fn qemu_debug_exit(v: u32) {
    if azos_limits::X86_QEMU_DEBUG_EXIT && crate::platform_impl::cpuid(1, 0).2 & (1 << 31) != 0 {
        outl(DEBUG_EXIT_PORT, v);
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: reading an architectural MSR at CPL0.
    unsafe { core::arch::asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
    ((hi as u64) << 32) | lo as u64
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn wrmsr(msr: u32, v: u64) {
    // SAFETY: writing an architectural MSR at CPL0.
    unsafe { core::arch::asm!("wrmsr", in("ecx") msr, in("eax") v as u32, in("edx") (v >> 32) as u32, options(nomem, nostack, preserves_flags)) };
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: rdtsc has no side effect.
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
    ((hi as u64) << 32) | lo as u64
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn rflags() -> u64 {
    let f: u64;
    // SAFETY: reads RFLAGS through the stack.
    unsafe { core::arch::asm!("pushfq", "pop {}", out(reg) f, options(nomem, preserves_flags)) };
    f
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn cli() {
    // SAFETY: masks maskable interrupts.
    unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn sti() {
    // SAFETY: unmasks maskable interrupts.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn hlt() {
    // SAFETY: waits for the next interrupt (forever with IF clear).
    unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)) };
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn outb(port: u16, v: u8) {
    // SAFETY: a port write; callers name the device's port.
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)) };
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: a port read; callers name the device's port.
    unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags)) };
    v
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn outw(port: u16, v: u16) {
    // SAFETY: a port write; callers name the device's port.
    unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack, preserves_flags)) };
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn inw(port: u16) -> u16 {
    let v: u16;
    // SAFETY: a port read; callers name the device's port.
    unsafe { core::arch::asm!("in ax, dx", in("dx") port, out("ax") v, options(nomem, nostack, preserves_flags)) };
    v
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn outl(port: u16, v: u32) {
    // SAFETY: a port write; callers name the device's port.
    unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack, preserves_flags)) };
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn inl(port: u16) -> u32 {
    let v: u32;
    // SAFETY: a port read; callers name the device's port.
    unsafe { core::arch::asm!("in eax, dx", in("dx") port, out("eax") v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Stop this CPU for good: interrupts off, then hlt forever.
#[cfg(target_arch = "x86_64")]
pub fn halt_forever() -> ! {
    loop {
        cli();
        hlt();
    }
}

/// Reset the machine the way no firmware can refuse: an empty IDT, then an
/// exception. The CPU cannot deliver it, nor the #DF that follows, and shuts
/// down; the chipset turns a shutdown cycle into a reset.
#[cfg(target_arch = "x86_64")]
pub fn triple_fault() -> ! {
    let idtr = [0u16; 5];
    // SAFETY: the end of this machine's life; nothing runs after the `int3`.
    unsafe { core::arch::asm!("lidt [{}]", "int3", in(reg) idtr.as_ptr(), options(nostack)) };
    halt_forever()
}

// ── The FS base (thread pointer) of a task, as the context switch handles it ─
//
// Pure, so the host tests run it (`tests/host/arch-tests`).
//
// Ring 3 cannot change its own FS base: CR4.FSGSBASE is off (`wrfsbase`
// is #UD) and no call sets it after the task starts. It is written by the
// kernel only: at a task's first entry (`SYS_THREAD_CREATE`'s `tls`, a
// Linux `clone` with `CLONE_SETTLS`, a fork's copy of its parent's), and
// cleared by exec. The scheduler keeps it per task slot and puts it back
// at a switch.

/// The FS base a switch from a task whose base is `prev` to one whose base
/// is `next` has to write, or `None` when the MSR already holds it: an MSR
/// write costs far more than the compare, and most switches are between
/// tasks with the same (usually zero) base.
pub const fn fs_base_to_load(prev: u64, next: u64) -> Option<u64> {
    if prev == next { None } else { Some(next) }
}

/// Is `base` a thread pointer a task may be given: a canonical address in the
/// lower (user) half under both 4- and 5-level paging. `wrmsr` of any other
/// value to `IA32_FS_BASE` raises #GP in the kernel.
pub const fn is_user_tls_base(base: u64) -> bool {
    base < (1 << 47)
}
