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
//! Kconfig `NR_CPUS`, `kernel/src/entry/x86_64/cpu_init.rs`): this crate only
//! names its layout, and the offsets the asm uses are injected from
//! `offset_of!` here, never copied by hand.

use crate::gdt::{Tss, GDT_ENTRIES};

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
pub const PERCPU_TSS_RSP0: usize = core::mem::offset_of!(PerCpu, tss) + crate::gdt::TSS_RSP0;

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
    crate::hw::wrmsr(crate::hw::IA32_GS_BASE, area as u64);
}

/// `lgdt` this table, reload CS (far return) and the data selectors, then
/// `ltr`. FS and GS are not reloaded: a selector load would reset their
/// bases (vendor-dependent), and boot.S left both null.
///
/// # Safety
/// `gdt` must stay mapped and unchanged for as long as the CPU runs, and
/// must have this module's layout ([`crate::gdt::table`]).
#[cfg(target_arch = "x86_64")]
pub unsafe fn load_gdt_and_tss(gdt: *const [u64; GDT_ENTRIES]) {
    use crate::gdt::{DescriptorPointer, KERNEL_CS, KERNEL_DS, TSS_SEL};
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
pub unsafe fn load_idt(idt: *const [[u64; 2]; crate::idt::VECTORS]) {
    let ptr = crate::gdt::DescriptorPointer {
        limit: (core::mem::size_of::<[[u64; 2]; crate::idt::VECTORS]>() - 1) as u16,
        base: idt as u64,
    };
    // SAFETY: per the caller.
    unsafe { core::arch::asm!("lidt [{}]", in(reg) &ptr, options(readonly, nostack, preserves_flags)) };
}

/// Arm `syscall`: EFER.SCE, the selectors (STAR), the entry (LSTAR), the
/// RFLAGS mask (FMASK), and a zero user GS base for the first `swapgs`.
#[cfg(target_arch = "x86_64")]
pub fn enable_syscall(entry: u64) {
    use crate::hw::{rdmsr, wrmsr};
    wrmsr(IA32_STAR, crate::gdt::STAR);
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
