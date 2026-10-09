// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AP start: INIT-SIPI-SIPI through the LAPIC to the MADT APIC ID of a dense
//! CPU number, through the real-mode trampoline in `ap_trampoline.S`.
//!
//! [`install`] (boot CPU, from `firmware_table`) copies the 16-bit stub to
//! the trampoline page (`platform().trampoline_pa`) and builds the AP's first
//! page tables: the first GiB in 2 MiB leaves (the kernel image), mapped
//! both 1:1 (the AP turns paging on at a physical address) and at
//! [`KERNEL_VA_OFFSET`] (the link address it jumps to before it loads the
//! kernel's own CR3, which maps no low RAM). Both are constant afterwards. [`hart_start`] then publishes the boot CPU's own
//! CR0/CR3/CR4/EFER, GDT, IDT and segments in [`X86_AP_BOOT`], sends the
//! IPIs and waits for the AP's ack, so one block serves every AP in turn.

#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicU64, Ordering};

use azos_arch_api::HartStartError;

use crate::encode;
use crate::mmu::KERNEL_VA_OFFSET;
use crate::platform_impl::platform;

core::arch::global_asm!(
    include_str!("ap_trampoline.S"),
    off_cr0 = const core::mem::offset_of!(ApBoot, cr0),
    off_cr3 = const core::mem::offset_of!(ApBoot, cr3),
    off_cr4 = const core::mem::offset_of!(ApBoot, cr4),
    off_efer = const core::mem::offset_of!(ApBoot, efer),
    off_gdtr = const core::mem::offset_of!(ApBoot, gdtr),
    off_idtr = const core::mem::offset_of!(ApBoot, idtr),
    off_cs = const core::mem::offset_of!(ApBoot, cs),
    off_ss = const core::mem::offset_of!(ApBoot, ss),
    off_entry = const core::mem::offset_of!(ApBoot, entry),
    off_arg = const core::mem::offset_of!(ApBoot, arg),
    off_ack = const core::mem::offset_of!(ApBoot, ack),
    kva = const KERNEL_VA_OFFSET,
    options(att_syntax)
);

unsafe extern "C" {
    static x86_ap_trampoline_start: u8;
    static x86_ap_trampoline_end: u8;
}

/// What the AP's 64-bit stage loads (layout read by `ap_trampoline.S`).
/// `gdtr`/`idtr` hold the 10-byte `sgdt`/`sidt` image in their first bytes.
#[repr(C, align(16))]
pub struct ApBoot {
    pub cr0: AtomicU64,
    pub cr3: AtomicU64,
    pub cr4: AtomicU64,
    pub efer: AtomicU64,
    pub gdtr: [AtomicU64; 2],
    pub idtr: [AtomicU64; 2],
    pub cs: AtomicU64,
    pub ss: AtomicU64,
    pub entry: AtomicU64,
    pub arg: AtomicU64,
    /// `arg + 1` once the AP has read the block; 0 while pending.
    pub ack: AtomicU64,
}

#[unsafe(no_mangle)]
pub static X86_AP_BOOT: ApBoot = ApBoot {
    cr0: AtomicU64::new(0),
    cr3: AtomicU64::new(0),
    cr4: AtomicU64::new(0),
    efer: AtomicU64::new(0),
    gdtr: [AtomicU64::new(0), AtomicU64::new(0)],
    idtr: [AtomicU64::new(0), AtomicU64::new(0)],
    cs: AtomicU64::new(0),
    ss: AtomicU64::new(0),
    entry: AtomicU64::new(0),
    arg: AtomicU64::new(0),
    ack: AtomicU64::new(0),
};

/// The trampoline's stack for its one far return (`X86_AP_STACK_TOP` is
/// its end); 16-byte aligned.
#[repr(C, align(16))]
pub struct ApStack(pub [u64; 8]);
#[unsafe(no_mangle)]
pub static mut X86_AP_STACK: ApStack = ApStack([0; 8]);
core::arch::global_asm!(
    ".pushsection .data.x86_ap_stack_top, \"aw\"",
    ".balign 8",
    ".globl X86_AP_STACK_TOP",
    ".set X86_AP_STACK_TOP, X86_AP_STACK + 64",
    ".popsection",
);

#[repr(C, align(4096))]
pub struct PageTable(pub [u64; 512]);

/// The AP's first tables (read by the 32-bit stage; the CPU sets A bits).
#[unsafe(no_mangle)]
pub static mut X86_AP_PML4: PageTable = PageTable([0; 512]);
#[unsafe(no_mangle)]
pub static mut X86_AP_PDPT: PageTable = PageTable([0; 512]);
#[unsafe(no_mangle)]
pub static mut X86_AP_PD: PageTable = PageTable([0; 512]);
/// The PDPT of the [`KERNEL_VA_OFFSET`] slot: its entry for the offset
/// names [`X86_AP_PD`] too.
#[unsafe(no_mangle)]
pub static mut X86_AP_PDPT_HI: PageTable = PageTable([0; 512]);
/// Above [`X86_AP_PML4`] when the boot CPU runs 5-level paging (LA57).
#[unsafe(no_mangle)]
pub static mut X86_AP_PML5: PageTable = PageTable([0; 512]);

const PTE_P: u64 = 1;
const PTE_RW: u64 = 1 << 1;
const PTE_PS: u64 = 1 << 7;
const ONE_GIB: u64 = 1 << 30;

/// Why [`install`] could not prepare AP start.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InstallError {
    /// No RAM page below 1 MiB is free of boot information.
    NoTrampolinePage,
    /// The kernel image or the AP tables are not inside the first GiB.
    KernelAboveFirstGiB,
}

/// The physical address of a kernel symbol (linked at [`KERNEL_VA_OFFSET`]
/// above it).
#[inline]
fn pa_of<T>(p: *const T) -> u64 {
    (p as u64).wrapping_sub(KERNEL_VA_OFFSET)
}

/// Copy the trampoline and build the AP tables.
///
/// # Safety
/// Boot CPU, from `firmware_table`, after `platform_impl::discover`, no AP
/// started; `kernel_end` is the image's end (a kernel VA). The trampoline
/// page is written at its [`KERNEL_VA_OFFSET`] alias (below 1 MiB, inside
/// the offset map at every stage of the boot).
pub unsafe fn install(kernel_end: usize) -> Result<u64, InstallError> {
    let tramp = platform().trampoline_pa.ok_or(InstallError::NoTrampolinePage)?;
    let pml4 = &raw mut X86_AP_PML4;
    let pdpt = &raw mut X86_AP_PDPT;
    let pdpt_hi = &raw mut X86_AP_PDPT_HI;
    let pd = &raw mut X86_AP_PD;
    if pa_of(kernel_end as *const u8) > ONE_GIB || pa_of(pd) >= ONE_GIB {
        return Err(InstallError::KernelAboveFirstGiB);
    }
    let kva = KERNEL_VA_OFFSET as usize;
    let table = |pa: u64| pa | PTE_P | PTE_RW;
    // SAFETY: the caller's contract: no AP runs, nothing else touches these.
    unsafe {
        // 1:1: PML4[0] -> PDPT[0] -> PD. At the offset: PML4[slot] ->
        // PDPT_HI[slot] -> the same PD. Under LA57 PML5[0] and PML5[slot]
        // both name the PML4.
        (*pml4).0[0] = table(pa_of(pdpt));
        (*pml4).0[crate::mmu::vpn(kva, 3)] = table(pa_of(pdpt_hi));
        let pml5 = &raw mut X86_AP_PML5;
        (*pml5).0[0] = table(pa_of(pml4));
        (*pml5).0[crate::mmu::vpn(kva, 4)] = table(pa_of(pml4));
        (*pdpt).0[0] = table(pa_of(pd));
        (*pdpt_hi).0[crate::mmu::vpn(kva, 2)] = table(pa_of(pd));
        for (i, e) in (*pd).0.iter_mut().enumerate() {
            *e = ((i as u64) << 21) | PTE_P | PTE_RW | PTE_PS;
        }
        let src = &raw const x86_ap_trampoline_start;
        let len = (&raw const x86_ap_trampoline_end) as usize - src as usize;
        core::ptr::copy_nonoverlapping(src, (tramp as usize + kva) as *mut u8, len);
    }
    Ok(tramp)
}

fn read_cr0() -> u64 {
    let v: u64;
    // SAFETY: reading a control register at CPL0.
    unsafe { core::arch::asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}
fn read_cr3() -> u64 {
    let v: u64;
    // SAFETY: as above.
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}
fn read_cr4() -> u64 {
    let v: u64;
    // SAFETY: as above.
    unsafe { core::arch::asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Publish this CPU's state for the next AP.
fn publish(entry: usize, arg: usize) {
    let b = &X86_AP_BOOT;
    let (mut gdtr, mut idtr) = ([0u64; 2], [0u64; 2]);
    let (cs, ss): (u16, u16);
    // SAFETY: sgdt/sidt store 10 bytes into the 16-byte buffers; segment
    // register reads have no side effect.
    unsafe {
        core::arch::asm!("sgdt [{}]", in(reg) gdtr.as_mut_ptr(), options(nostack, preserves_flags));
        core::arch::asm!("sidt [{}]", in(reg) idtr.as_mut_ptr(), options(nostack, preserves_flags));
        core::arch::asm!("mov {0:x}, cs", "mov {1:x}, ss", out(reg) cs, out(reg) ss, options(nomem, nostack, preserves_flags));
    }
    b.cr0.store(read_cr0(), Ordering::Relaxed);
    // PCID bits off: CR4.PCIDE may only be set with CR3[11:0] clear.
    b.cr3.store(read_cr3() & !0xFFF, Ordering::Relaxed);
    b.cr4.store(read_cr4(), Ordering::Relaxed);
    b.efer.store(crate::hw::rdmsr(0xC000_0080), Ordering::Relaxed);
    for i in 0..2 {
        b.gdtr[i].store(gdtr[i], Ordering::Relaxed);
        b.idtr[i].store(idtr[i], Ordering::Relaxed);
    }
    b.cs.store(cs as u64, Ordering::Relaxed);
    b.ss.store(ss as u64, Ordering::Relaxed);
    b.entry.store(entry as u64, Ordering::Relaxed);
    b.arg.store(arg as u64, Ordering::Relaxed);
    // Release: every field above is visible before the AP can see ack == 0
    // and before the IPI that starts it.
    b.ack.store(0, Ordering::Release);
}

fn acked(arg: usize) -> bool {
    X86_AP_BOOT.ack.load(Ordering::Acquire) == arg as u64 + 1
}

/// Start dense CPU `cpu` at `entry` (64-bit, kernel tables, `%rdi = arg`,
/// no stack: the entry sets its own) with INIT, then up to two STARTUPs
/// (Intel's MP initialization protocol), and wait for its ack.
pub fn hart_start(cpu: usize, entry: usize, arg: usize) -> Result<(), HartStartError> {
    let p = platform();
    let apic_id = p.apic_id(cpu).ok_or(HartStartError::InvalidHartId)?;
    if cpu == 0 || apic_id == crate::apic::id() {
        return Err(HartStartError::AlreadyOn);
    }
    let page = p.trampoline_pa.ok_or(HartStartError::Other(-2))?;
    let sipi = encode::icr_sipi(page).ok_or(HartStartError::Other(-2))?;
    publish(entry, arg);

    if !crate::apic::send_raw(apic_id, encode::icr_init()) {
        return Err(HartStartError::Denied);
    }
    crate::apic::send_raw(apic_id, encode::icr_init_deassert());
    crate::timer::udelay(azos_limits::X86_AP_INIT_DELAY_US);
    for _ in 0..2 {
        crate::apic::send_raw(apic_id, sipi);
        crate::timer::udelay(azos_limits::X86_AP_SIPI_DELAY_US);
        if acked(arg) {
            return Ok(());
        }
    }
    let deadline = crate::timer::tsc_after_us(azos_limits::X86_AP_START_TIMEOUT_MS.saturating_mul(1000));
    while crate::hw::rdtsc() < deadline {
        if acked(arg) {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(HartStartError::Other(-3))
}
