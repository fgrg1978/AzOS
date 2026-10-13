// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AP start: INIT-SIPI-SIPI through the LAPIC to the MADT APIC ID of a dense
//! CPU number, through the real-mode trampoline in `ap_trampoline.S`.
//!
//! [`install`] (boot CPU, from `firmware_table`) copies the whole trampoline
//! (its 16-, 32- and 64-bit stages, GDT and parameter block: position
//! independent) to the trampoline page (`platform().trampoline_pa`), patches
//! the parameters that depend on where the page and the tables are, and
//! builds the AP's first page tables: the first GiB in 2 MiB leaves 1:1 (the
//! trampoline page, where the AP turns paging on) and the kernel image at its
//! link address, through the same image map the Limine entry boots on
//! ([`build_image_map`]: the image is wherever the loader put it, so its
//! frames are named, not assumed). Both are constant afterwards.
//! [`hart_start`] then publishes the boot CPU's own CR0/CR3/CR4/EFER, GDT,
//! IDT and segments in [`X86_AP_BOOT`], sends the IPIs and waits for the
//! AP's ack, so one block serves every AP in turn.

#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use azos_arch_api::HartStartError;

use crate::encode;
use crate::mmu::{fill_image_map, image_phys, ImageMapError, KERNEL_VA_OFFSET};
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
    options(att_syntax)
);

unsafe extern "C" {
    static x86_ap_trampoline_start: u8;
    static x86_ap_trampoline_end: u8;
    // The parameter block inside the copied page (ap_trampoline.S), patched by `install`.
    static x86_ap_tr_gdtr: u8;
    static x86_ap_tr_far32: u8;
    static x86_ap_tr_far64: u8;
    static x86_ap_tr_cr3: u8;
    static x86_ap_tr_la57: u8;
    static x86_ap_gdt: u8;
    static x86_ap_start32: u8;
    static x86_ap_start64: u8;
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
/// The PDPT of the [`KERNEL_VA_OFFSET`] slot: its entry for the image's
/// first GiB names [`X86_IMAGE_PD`].
#[unsafe(no_mangle)]
pub static mut X86_AP_PDPT_HI: PageTable = PageTable([0; 512]);
/// Above [`X86_AP_PML4`] when the boot CPU runs 5-level paging (LA57).
#[unsafe(no_mangle)]
pub static mut X86_AP_PML5: PageTable = PageTable([0; 512]);

/// Page tables of the image map: 2 MiB of image each, plus one for a start
/// that is not 2 MiB-aligned (Kconfig `X86_IMAGE_MAX_MIB`).
pub const IMAGE_PT_PAGES: usize = (azos_limits::X86_IMAGE_MAX_MIB as usize).div_ceil(2) + 1;

/// The page directory of the image's first GiB, and its tables: the boot
/// CPU's map under Limine (`limine_prepare`) and every AP's (`install`).
#[unsafe(no_mangle)]
pub static mut X86_IMAGE_PD: PageTable = PageTable([0; 512]);
#[unsafe(no_mangle)]
pub static mut X86_IMAGE_PTS: [PageTable; IMAGE_PT_PAGES] = [const { PageTable([0; 512]) }; IMAGE_PT_PAGES];

/// The image map exists: the Limine entry built it and boots on it, so
/// `install` must not build it again under that CPU (the map does not change).
static IMAGE_MAP_BUILT: AtomicBool = AtomicBool::new(false);

const PTE_P: u64 = 1;
const PTE_RW: u64 = 1 << 1;
const PTE_PS: u64 = 1 << 7;
const FOUR_GIB: u64 = 1 << 32;

/// Why [`install`] could not prepare AP start.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InstallError {
    /// No RAM page below 1 MiB is free of boot information.
    NoTrampolinePage,
    /// A page table of the AP start (or the image map) is above 4 GiB: the
    /// 32-bit stage loads CR3 with a 32-bit move.
    TablesAbove4GiB,
    /// The image is larger than Kconfig `X86_IMAGE_MAX_MIB` or leaves the
    /// first GiB of its window.
    Image(ImageMapError),
}

/// The physical address of a kernel symbol: an image address, translated
/// through the slide the boot recorded ([`crate::mmu::image_phys`]).
#[inline]
fn pa_of<T>(p: *const T) -> u64 {
    image_phys(p as u64)
}

/// Build the image map ([`X86_IMAGE_PD`], [`X86_IMAGE_PTS`]) for the image
/// `[start, end)` (kernel virtual addresses) at the recorded slide; the
/// physical address of the directory. Built once; later calls return the
/// directory.
///
/// # Safety
/// Boot CPU, before the map is loaded by another CPU or CR3 names it
/// again; the slide ([`crate::mmu::set_image_slide`]) is recorded.
pub unsafe fn build_image_map(start: usize, end: usize) -> Result<u64, InstallError> {
    let pd = &raw mut X86_IMAGE_PD;
    if IMAGE_MAP_BUILT.load(Ordering::Acquire) {
        return Ok(pa_of(pd));
    }
    let pts = &raw mut X86_IMAGE_PTS;
    // SAFETY: the caller's contract; `PageTable` is a 4096-byte, 4096-aligned
    // array of 512 words, so the slice reads as `[u64; 512]` rows.
    let rows = unsafe { core::slice::from_raw_parts_mut(pts as *mut [u64; 512], IMAGE_PT_PAGES) };
    let tables_pa = |k: usize| pa_of(unsafe { (pts as *const PageTable).add(k) });
    // SAFETY: as above.
    fill_image_map(unsafe { &mut (*pd).0 }, rows, tables_pa, start as u64, end as u64,
                   crate::mmu::image_slide())
        .map_err(InstallError::Image)?;
    let pa = pa_of(pd);
    if pa >= FOUR_GIB || tables_pa(IMAGE_PT_PAGES - 1) >= FOUR_GIB {
        return Err(InstallError::TablesAbove4GiB);
    }
    IMAGE_MAP_BUILT.store(true, Ordering::Release);
    Ok(pa)
}

/// Copy the trampoline, patch its parameters and build the AP tables.
///
/// # Safety
/// Boot CPU, from `firmware_table`, after `platform_impl::discover`, no AP
/// started; `[image_start, image_end)` is the kernel image (kernel virtual
/// addresses). The trampoline page is written through the direct map (boot
/// tables map PA 0..4 GiB there).
pub unsafe fn install(image_start: usize, image_end: usize) -> Result<u64, InstallError> {
    let tramp = platform().trampoline_pa.ok_or(InstallError::NoTrampolinePage)?;
    let pml4 = &raw mut X86_AP_PML4;
    let pdpt = &raw mut X86_AP_PDPT;
    let pdpt_hi = &raw mut X86_AP_PDPT_HI;
    let pd = &raw mut X86_AP_PD;
    let pml5 = &raw mut X86_AP_PML5;
    // SAFETY: the caller's contract: no AP runs, nothing else touches these.
    let image_pd = unsafe { build_image_map(image_start, image_end)? };
    if [pml4, pdpt, pdpt_hi, pd, pml5].iter().any(|&t| pa_of(t) >= FOUR_GIB) {
        return Err(InstallError::TablesAbove4GiB);
    }
    let kva = KERNEL_VA_OFFSET as usize;
    let table = |pa: u64| pa | PTE_P | PTE_RW;
    // SAFETY: the caller's contract: no AP runs, nothing else touches these.
    unsafe {
        // 1:1: PML4[0] -> PDPT[0] -> PD (the first GiB, for the trampoline
        // page). At the offset: PML4[slot] -> PDPT_HI[slot] -> the image
        // directory. Under LA57 PML5[0] and PML5[slot] both name the PML4.
        (*pml4).0[0] = table(pa_of(pdpt));
        (*pml4).0[crate::mmu::vpn(kva, 3)] = table(pa_of(pdpt_hi));
        (*pml5).0[0] = table(pa_of(pml4));
        (*pml5).0[crate::mmu::vpn(kva, 4)] = table(pa_of(pml4));
        (*pdpt).0[0] = table(pa_of(pd));
        (*pdpt_hi).0[crate::mmu::vpn(kva, 2)] = table(image_pd);
        for (i, e) in (*pd).0.iter_mut().enumerate() {
            *e = ((i as u64) << 21) | PTE_P | PTE_RW | PTE_PS;
        }

        // The page: the stages, then the parameters that name this page and
        // these tables (the stage code is position independent).
        let src = &raw const x86_ap_trampoline_start;
        let len = (&raw const x86_ap_trampoline_end) as usize - src as usize;
        let dst = (tramp + crate::mmu::DIRECT_MAP_BASE) as usize as *mut u8;
        core::ptr::copy_nonoverlapping(src, dst, len);
        let off = |sym: *const u8| sym as usize - src as usize;
        let put32 = |sym: *const u8, v: u32| (dst.add(off(sym)) as *mut u32).write_unaligned(v);
        let here = |sym: *const u8| tramp as u32 + off(sym) as u32;
        // lgdt's base, the 32-bit and 64-bit far-jump offsets (their selectors
        // are in the stub), CR3 for the AP's depth and the LA57 flag.
        put32((&raw const x86_ap_tr_gdtr).add(2), here(&raw const x86_ap_gdt));
        put32(&raw const x86_ap_tr_far32, here(&raw const x86_ap_start32));
        put32(&raw const x86_ap_tr_far64, here(&raw const x86_ap_start64));
        let la57 = read_cr4() & (1 << 12) != 0;
        put32(&raw const x86_ap_tr_cr3, if la57 { pa_of(pml5) } else { pa_of(pml4) } as u32);
        put32(&raw const x86_ap_tr_la57, la57 as u32);
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
