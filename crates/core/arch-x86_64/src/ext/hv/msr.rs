// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The MSRs a guest touches, and what it gets.
//!
//! The permission map ([`build_msrpm`]) intercepts **every** MSR except the
//! ones whose state the VMCB already holds and `VMRUN` swaps: the segment
//! bases, the `SYSCALL` / `SYSENTER` MSRs. Those run at full speed; the rest
//! exit, and [`read`] / [`write`] decide:
//!
//! | MSR | answer |
//! |-----|--------|
//! | `EFER` | the VMCB's, without `SVME` (the guest believes it has no SVM); a write is checked against the bits CPUID offers, `LMA` is the hardware's, `LME` cannot change under paging, and `SVME` stays set underneath |
//! | `PAT` | the guest's PAT (`G_PAT`), each byte a valid memory type |
//! | `TSC` | host TSC plus the VMCB offset; a write moves the offset |
//! | `APIC_BASE`, `TSC_DEADLINE`, `0x800..0x900` | the vLAPIC ([`super::apic`]) |
//! | AMD patch level, `DE_CFG` | read as zero, writes dropped: the mitigation code of an AMD guest looks at them, and nothing they could hold matters to a guest that cannot touch the hardware |
//! | anything else | `#GP(0)`, as on a CPU without the MSR |
//!
//! Pure over the VMCB and a [`LocalApic`], so the host tests script the
//! accesses. The caller does the `RDMSR` / `WRMSR` register plumbing
//! ([`super::serve`]).

use super::apic::{is_apic_msr, Gp, LocalApic};
use super::svm::{efer, off, Vmcb, MSRPM_BYTES};

pub const MSR_TSC: u32 = 0x10;
pub const MSR_AMD_PATCH_LEVEL: u32 = 0x8B;
pub const MSR_SYSENTER_CS: u32 = 0x174;
pub const MSR_SYSENTER_ESP: u32 = 0x175;
pub const MSR_SYSENTER_EIP: u32 = 0x176;
pub const MSR_PAT: u32 = 0x277;
pub const MSR_EFER: u32 = 0xC000_0080;
pub const MSR_STAR: u32 = 0xC000_0081;
pub const MSR_LSTAR: u32 = 0xC000_0082;
pub const MSR_CSTAR: u32 = 0xC000_0083;
pub const MSR_SFMASK: u32 = 0xC000_0084;
pub const MSR_FS_BASE: u32 = 0xC000_0100;
pub const MSR_GS_BASE: u32 = 0xC000_0101;
pub const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;
pub const MSR_AMD_DE_CFG: u32 = 0xC001_1029;

/// The MSRs the guest reads and writes without an exit: the VMCB holds them.
pub const PASSTHROUGH: [u32; 10] = [
    MSR_SYSENTER_CS,
    MSR_SYSENTER_ESP,
    MSR_SYSENTER_EIP,
    MSR_STAR,
    MSR_LSTAR,
    MSR_CSTAR,
    MSR_SFMASK,
    MSR_FS_BASE,
    MSR_GS_BASE,
    MSR_KERNEL_GS_BASE,
];

/// `EFER` bits a guest may write: `SCE`, `LME`, `NXE`.
pub const EFER_WRITABLE: u64 = 1 | efer::LME | 1 << 11;

/// Where an MSR's two bits sit in the permission map: the byte, and the bit
/// of the read intercept in it (the write intercept is the next bit). `None`
/// for an MSR outside the three ranges the map covers (always intercepted).
const fn msrpm_bit(msr: u32) -> Option<(usize, u32)> {
    let (base, first) = match msr {
        0..=0x1FFF => (0x000, 0),
        0xC000_0000..=0xC000_1FFF => (0x800, 0xC000_0000),
        0xC001_0000..=0xC001_1FFF => (0x1000, 0xC001_0000),
        _ => return None,
    };
    let bit = (msr - first) as usize * 2;
    Some((base + bit / 8, (bit % 8) as u32))
}

/// Allow the guest to read (`rd`) and/or write (`wr`) `msr` without an exit.
fn allow(pm: &mut [u8; MSRPM_BYTES], msr: u32, rd: bool, wr: bool) {
    let Some((byte, bit)) = msrpm_bit(msr) else { return };
    if rd {
        pm[byte] &= !(1 << bit);
    }
    if wr {
        pm[byte] &= !(1 << (bit + 1));
    }
}

/// Fill `pm` with the MSR permission map of a guest: everything intercepted,
/// [`PASSTHROUGH`] open for both directions, and the TSC open for reads (the
/// hardware adds the VMCB's offset; a write must move the offset, not the
/// host's counter).
pub fn build_msrpm(pm: &mut [u8; MSRPM_BYTES]) {
    pm.fill(0xFF);
    for m in PASSTHROUGH {
        allow(pm, m, true, true);
    }
    allow(pm, MSR_TSC, true, false);
}

/// Is the read (`write == false`) or write of `msr` intercepted by `pm`?
pub fn intercepted(pm: &[u8; MSRPM_BYTES], msr: u32, write: bool) -> bool {
    match msrpm_bit(msr) {
        Some((byte, bit)) => pm[byte] >> (bit + write as u32) & 1 != 0,
        None => true,
    }
}

/// Valid memory type encodings of a PAT entry: UC, WC, WT, WP, WB, UC-.
const fn pat_valid(pat: u64) -> bool {
    let mut i = 0;
    while i < 8 {
        let t = (pat >> (i * 8)) as u8;
        if !(t == 0 || t == 1 || t == 4 || t == 5 || t == 6 || t == 7) {
            return false;
        }
        i += 1;
    }
    true
}

/// `RDMSR` of `msr` for a guest. `host_tsc` is the host's counter now.
pub fn read(vmcb: &Vmcb, apic: &mut dyn LocalApic, msr: u32, host_tsc: u64) -> Result<u64, Gp> {
    let guest_tsc = host_tsc.wrapping_add(vmcb.rd64(off::TSC_OFFSET));
    match msr {
        MSR_EFER => Ok(vmcb.rd64(off::EFER) & !efer::SVME),
        MSR_PAT => Ok(vmcb.rd64(off::G_PAT)),
        MSR_TSC => Ok(guest_tsc),
        MSR_AMD_PATCH_LEVEL | MSR_AMD_DE_CFG => Ok(0),
        m if is_apic_msr(m) => apic.msr_read(m, guest_tsc),
        _ => Err(Gp),
    }
}

/// `WRMSR` of `val` to `msr` for a guest.
pub fn write(vmcb: &mut Vmcb, apic: &mut dyn LocalApic, msr: u32, val: u64, host_tsc: u64) -> Result<(), Gp> {
    let guest_tsc = host_tsc.wrapping_add(vmcb.rd64(off::TSC_OFFSET));
    match msr {
        MSR_EFER => write_efer(vmcb, val),
        MSR_PAT => {
            if !pat_valid(val) {
                return Err(Gp);
            }
            vmcb.wr64(off::G_PAT, val);
            Ok(())
        }
        MSR_TSC => {
            vmcb.wr64(off::TSC_OFFSET, val.wrapping_sub(host_tsc));
            Ok(())
        }
        MSR_AMD_PATCH_LEVEL | MSR_AMD_DE_CFG => Ok(()),
        m if is_apic_msr(m) => apic.msr_write(m, val, guest_tsc),
        _ => Err(Gp),
    }
}

fn write_efer(vmcb: &mut Vmcb, val: u64) -> Result<(), Gp> {
    let cur = vmcb.rd64(off::EFER);
    // `LMA` is the hardware's (writing it is accepted and ignored: the AP
    // trampoline writes back what it read); `SVME` and every other bit are
    // not offered by CPUID.
    if val & !(EFER_WRITABLE | efer::LMA) != 0 {
        return Err(Gp);
    }
    // Long mode cannot be switched on or off under paging.
    let paging = vmcb.rd64(off::CR0) & super::svm::cr0::PG != 0;
    if paging && (val ^ cur) & efer::LME != 0 {
        return Err(Gp);
    }
    // `SVME` must stay set in the VMCB whatever the guest wrote: `VMRUN` checks it.
    vmcb.wr64(off::EFER, (cur & efer::LMA) | (val & EFER_WRITABLE) | efer::SVME);
    Ok(())
}
