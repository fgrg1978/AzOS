// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 FP/SIMD state (Kconfig `FP_XSAVE_EAGER`). **Never a first-use
//! trap**: CR0.TS stays clear and #NM is never armed. Lazy switching
//! (CR0.TS and a #NM trap on first use) leaks the previous task's registers
//! through speculation (LazyFP, CVE-2018-3665); Linux made eager the
//! default in 4.6 and removed the lazy mode in 4.14.
//!
//! What the kernel does (`kernel/src/entry/x86_64/fp.rs`) is Linux's own
//! shape since 5.2: the outgoing task's state is SAVED at every context
//! switch that leaves FP state live, and the incoming task's is RESTORED on
//! its way back to ring 3, before any user instruction runs. The kernel is
//! soft-float, so between the two nothing reads or writes the registers;
//! a kernel task that never returns to ring 3 costs no restore.
//!
//! aarch64 switches lazily (`kernel/src/entry/aarch64/fp_lazy.rs`,
//! `CPACR_EL1.FPEN` trap on first use): that is a per-ISA choice, so the
//! shared scheduler must not assume either.
//!
//! This module holds the CPU side: CR0/CR4/XCR0 setup ([`init_cpu`]), the
//! save and restore instructions, and the initial-state image. The areas
//! (one per task slot, Kconfig `X86_XSAVE_AREA_BYTES`) are the kernel's.

use core::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};

/// The FXSAVE legacy region (x87 + SSE).
pub const LEGACY_BYTES: usize = 512;
/// The XSAVE header that follows it.
pub const XSAVE_HEADER_BYTES: usize = 64;
/// Byte offset of FCW in the legacy region.
const FCW_OFFSET: usize = 0;
/// Byte offset of MXCSR in the legacy region.
const MXCSR_OFFSET: usize = 24;
/// x87 control word after `fninit`.
pub const FCW_INIT: u16 = 0x037F;
/// MXCSR at reset: every SIMD exception masked, round to nearest.
pub const MXCSR_INIT: u32 = 0x1F80;
/// XSAVE areas must be 64-byte aligned (FXSAVE: 16).
pub const AREA_ALIGN: usize = 64;

// XCR0 components a ring-3 task may use.
pub const XCR0_X87: u64 = 1 << 0;
pub const XCR0_SSE: u64 = 1 << 1;
pub const XCR0_AVX: u64 = 1 << 2;
/// AVX-512: opmask, ZMM_Hi256, Hi16_ZMM (enabled together, with AVX).
pub const XCR0_AVX512: u64 = (1 << 5) | (1 << 6) | (1 << 7);

/// How [`save_eager`] / [`restore_eager`] move the state on this machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SaveMode {
    /// FXSAVE64 / FXRSTOR64: no XSAVE (x87 + SSE only).
    Fxsave = 0,
    /// XSAVE64 / XRSTOR64.
    Xsave = 1,
    /// XSAVEOPT64 / XRSTOR64: skips components in their init state or
    /// unmodified since this area's last XRSTOR.
    Xsaveopt = 2,
}

static MODE: AtomicU8 = AtomicU8::new(SaveMode::Fxsave as u8);
static XCR0: AtomicU64 = AtomicU64::new(XCR0_X87 | XCR0_SSE);
static AREA_BYTES: AtomicUsize = AtomicUsize::new(LEGACY_BYTES);

/// The XCR0 components chosen, from the largest set whose XSAVE area fits
/// in `max_area` bytes: AVX-512, else AVX, else x87+SSE. `supported` is
/// CPUID.(0xD,0):EDX:EAX; `size_of` gives the area size XCR0 = mask needs.
/// Pure (host-tested): the CPU side feeds it CPUID.
pub fn choose_xcr0(supported: u64, max_area: usize, mut size_of: impl FnMut(u64) -> usize) -> Option<(u64, usize)> {
    let base = XCR0_X87 | XCR0_SSE;
    if supported & base != base {
        return None;
    }
    let mut candidates = [base; 3];
    if supported & XCR0_AVX != 0 {
        candidates[1] = base | XCR0_AVX;
        candidates[0] = if supported & XCR0_AVX512 == XCR0_AVX512 {
            base | XCR0_AVX | XCR0_AVX512
        } else {
            candidates[1]
        };
    }
    candidates.into_iter().map(|m| (m, size_of(m))).find(|&(_, size)| size <= max_area)
}

/// Write the initial FP state into `area` (what `fninit` + reset MXCSR
/// leave, with an all-zero XSAVE header: every component in its init state).
pub fn init_area(area: &mut [u8]) {
    area.fill(0);
    area[FCW_OFFSET..FCW_OFFSET + 2].copy_from_slice(&FCW_INIT.to_le_bytes());
    area[MXCSR_OFFSET..MXCSR_OFFSET + 4].copy_from_slice(&MXCSR_INIT.to_le_bytes());
}

/// The save mode [`init_cpu`] chose.
pub fn mode() -> SaveMode {
    match MODE.load(Ordering::Relaxed) {
        2 => SaveMode::Xsaveopt,
        1 => SaveMode::Xsave,
        _ => SaveMode::Fxsave,
    }
}

/// The enabled XCR0 components.
pub fn xcr0() -> u64 {
    XCR0.load(Ordering::Relaxed)
}

/// Bytes of the area the chosen components need.
pub fn area_bytes() -> usize {
    AREA_BYTES.load(Ordering::Relaxed)
}

/// Why [`init_cpu`] could not give ring 3 an FP state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FpuInitError {
    /// Even x87+SSE (512 B legacy + 64 B header) does not fit the area.
    AreaTooSmall { needed: usize, max: usize },
}

#[cfg(target_arch = "x86_64")]
fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    // CPUID is unprivileged and side-effect free (a safe intrinsic).
    let r = core::arch::x86_64::__cpuid_count(leaf, sub);
    (r.eax, r.ebx, r.ecx, r.edx)
}

#[cfg(target_arch = "x86_64")]
fn xsetbv(xcr0: u64) {
    // SAFETY: CPL0 with CR4.OSXSAVE set; `xcr0` passed `choose_xcr0`
    // (x87|SSE always, AVX-512 only with AVX).
    unsafe {
        core::arch::asm!("xsetbv", in("ecx") 0u32, in("eax") xcr0 as u32, in("edx") (xcr0 >> 32) as u32,
            options(nomem, nostack, preserves_flags));
    }
}

/// Make FP/SIMD usable by ring 3 on the calling CPU: CR0.MP|NE, CR0.EM|TS
/// clear, CR4.OSFXSR|OSXMMEXCPT, and with XSAVE: CR4.OSXSAVE and XCR0 =
/// the largest component set whose area fits `max_area` (Kconfig
/// `X86_XSAVE_AREA_BYTES`). `use_xsaveopt` is the X86_XSAVEOPT policy's
/// verdict. Every CPU runs it; the boot CPU's choice is the system's.
#[cfg(target_arch = "x86_64")]
pub fn init_cpu(max_area: usize, use_xsaveopt: bool) -> Result<SaveMode, FpuInitError> {
    const CR0_MP: u64 = 1 << 1;
    const CR0_EM: u64 = 1 << 2;
    const CR0_TS: u64 = 1 << 3;
    const CR0_NE: u64 = 1 << 5;
    const CR4_OSFXSR: u64 = 1 << 9;
    const CR4_OSXMMEXCPT: u64 = 1 << 10;
    const CR4_OSXSAVE: u64 = 1 << 18;
    const CPUID1_ECX_XSAVE: u32 = 1 << 26;
    const CPUIDD1_EAX_XSAVEOPT: u32 = 1 << 0;

    let needed = LEGACY_BYTES + XSAVE_HEADER_BYTES;
    if max_area < needed {
        return Err(FpuInitError::AreaTooSmall { needed, max: max_area });
    }
    let has_xsave = cpuid(1, 0).2 & CPUID1_ECX_XSAVE != 0;
    // SAFETY: CPL0 control-register updates that only enable FP/SSE for
    // ring 3; the kernel itself is soft-float and executes neither.
    unsafe {
        let mut cr0: u64;
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        cr0 = (cr0 | CR0_MP | CR0_NE) & !(CR0_EM | CR0_TS);
        core::arch::asm!("mov cr0, {}", in(reg) cr0, options(nostack, preserves_flags));
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        cr4 |= CR4_OSFXSR | CR4_OSXMMEXCPT;
        if has_xsave {
            cr4 |= CR4_OSXSAVE;
        }
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
        core::arch::asm!("fninit", options(nomem, nostack));
    }
    if !has_xsave {
        MODE.store(SaveMode::Fxsave as u8, Ordering::Relaxed);
        XCR0.store(XCR0_X87 | XCR0_SSE, Ordering::Relaxed);
        AREA_BYTES.store(LEGACY_BYTES, Ordering::Relaxed);
        return Ok(SaveMode::Fxsave);
    }
    let (eax, _, _, edx) = cpuid(0xD, 0);
    let supported = ((edx as u64) << 32) | eax as u64;
    // CPUID.(0xD,0):EBX is the area size for the XCR0 currently set.
    let chosen = choose_xcr0(supported, max_area, |m| {
        xsetbv(m);
        cpuid(0xD, 0).1 as usize
    });
    let Some((mask, bytes)) = chosen else {
        xsetbv(XCR0_X87 | XCR0_SSE);
        return Err(FpuInitError::AreaTooSmall { needed: cpuid(0xD, 0).1 as usize, max: max_area });
    };
    xsetbv(mask);
    let mode = if use_xsaveopt && cpuid(0xD, 1).0 & CPUIDD1_EAX_XSAVEOPT != 0 {
        SaveMode::Xsaveopt
    } else {
        SaveMode::Xsave
    };
    XCR0.store(mask, Ordering::Relaxed);
    AREA_BYTES.store(bytes, Ordering::Relaxed);
    MODE.store(mode as u8, Ordering::Relaxed);
    Ok(mode)
}

/// Save the current FP/SIMD state into `area` (XSAVEOPT64, else XSAVE64
/// with the XCR0 mask; FXSAVE64 without XSAVE).
///
/// # Safety
/// `area` must be a 64-byte-aligned area of at least [`area_bytes`] bytes,
/// owned by the caller with interrupts masked.
pub unsafe fn save_eager(area: *mut u8) {
    #[cfg(target_arch = "x86_64")]
    {
        let m = xcr0();
        // SAFETY: per the caller.
        unsafe {
            match mode() {
                SaveMode::Xsaveopt => core::arch::asm!("xsaveopt64 [{}]", in(reg) area,
                    in("eax") m as u32, in("edx") (m >> 32) as u32, options(nostack, preserves_flags)),
                SaveMode::Xsave => core::arch::asm!("xsave64 [{}]", in(reg) area,
                    in("eax") m as u32, in("edx") (m >> 32) as u32, options(nostack, preserves_flags)),
                SaveMode::Fxsave => core::arch::asm!("fxsave64 [{}]", in(reg) area,
                    options(nostack, preserves_flags)),
            }
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = area;
        todo!("x86_64: fpu::save_eager: XSAVEOPT / XSAVE / FXSAVE")
    }
}

/// Restore `area` (XRSTOR64 with the XCR0 mask, or FXRSTOR64).
///
/// # Safety
/// `area` must hold a state [`save_eager`] wrote, or [`init_area`]'s, with
/// the alignment and size [`save_eager`] requires.
pub unsafe fn restore_eager(area: *const u8) {
    #[cfg(target_arch = "x86_64")]
    {
        let m = xcr0();
        // SAFETY: per the caller.
        unsafe {
            match mode() {
                SaveMode::Xsaveopt | SaveMode::Xsave => core::arch::asm!("xrstor64 [{}]", in(reg) area,
                    in("eax") m as u32, in("edx") (m >> 32) as u32, options(readonly, nostack, preserves_flags)),
                SaveMode::Fxsave => core::arch::asm!("fxrstor64 [{}]", in(reg) area,
                    options(readonly, nostack, preserves_flags)),
            }
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = area;
        todo!("x86_64: fpu::restore_eager: XRSTOR / FXRSTOR")
    }
}
