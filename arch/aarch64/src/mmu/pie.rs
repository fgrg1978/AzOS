// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Stage-1 indirect permissions on aarch64 (Kconfig `A64_S1PIE`, FEAT_S1PIE).
//!
//! With `TCR2_EL1.PIE` set, a leaf's UXN (54), PXN (53), DBM (51) and AP\[1\]
//! (6) bits are a 4-bit index ([`pi_index`]); `PIR_EL1` holds EL1's 4-bit
//! permission for each index and `PIRE0_EL1` EL0's. A GCS page (the guarded
//! control stack, FEAT_GCS) exists only as such a permission ([`PIE_GCS`]).
//!
//! **The scheme.** An `A64_S1PIE` build sets DBM on every writable leaf and
//! on no read-only or copy-on-write one (`mmu::WRITE_DBM`), so the index says
//! by itself whether a page is writable and AP\[2\] (bit 7, `nDirty` under
//! PIE) always agrees with it. The page-table code then produces eight
//! indices, kernel ones with UXN and no AP\[1\], user ones with PXN and
//! AP\[1\]; [`PIR_EL1_VALUE`] and [`PIRE0_EL1_VALUE`] give each the
//! permissions the direct bits give it ([`direct`]), derived from that same
//! model rather than written out, with the overlay applied (the `_O`
//! encodings: `A64_POE`'s pool keeps its write-deny). Every other index grants
//! nothing, but [`GCS_INDEX`]. `TCR_EL1.HD` is never set, so DBM has no effect
//! where PIE is off and the same words are right under both schemes.
//!
//! **Premises** the encodings do not settle (the Arm ARM was not reachable;
//! Linux's headers give the field positions and nibble values only): PAN
//! applies to a page EL0 can read or write under `PIRE0_EL1`, as it does to
//! AP\[1\] under the direct bits (the kernel and user indices give EL0 the same
//! access either way, so the outcome is the same if PAN also counts EL0
//! execute; Linux's `PIE_E0` grants EL0 read on its user pages and its uaccess
//! still relies on PAN; a ktest checks it on the S1PIE row). This one carries
//! security weight: were it wrong, EL1 would reach user pages freely with PIE
//! on. Hierarchical permissions play no part: no table descriptor here carries
//! APTable/XNTable (`make_table`, a host row holds it). Whether bit 7 removes write under PIE does not
//! matter: no word the code builds has bit 7 set on a writable index.
//!
//! EL2 must let EL1 at the registers: `HCRX_EL2.TCR2En` and the
//! `HFGRTR_EL2`/`HFGWTR_EL2` n-bits `nPIR_EL1`, `nPIRE0_EL1` (`mmu/boot.rs`).
//!
//! Encodings: Linux arch/arm64/include/asm/sysreg.h (`PIE_*`,
//! `PIRx_ELx_PERM_SHIFT`), pgtable-hwdef.h (`PTE_PI_IDX_0..3`) and
//! arch/arm64/tools/sysreg (`TCR2_EL1.PIE` 1, `PIR_EL1` S3_0_C10_C2_3,
//! `PIRE0_EL1` S3_0_C10_C2_2, `HFGRTR_EL2` nPIR_EL1 58 and nPIRE0_EL1 57).

use super::pte_fmt::{AP_EL0, AP_RO, DBM, PXN, UXN};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The leaf bits of the index, low bit first: AP\[1\], DBM, PXN, UXN.
pub const PI_BITS: [u32; 4] = [6, 51, 53, 54];

/// The permission index of the leaf `word`.
pub const fn pi_index(word: u64) -> usize {
    let mut i = 0;
    let mut k = 0;
    while k < 4 {
        i |= (((word >> PI_BITS[k]) & 1) as usize) << k;
        k += 1;
    }
    i
}

/// `PIR_EL1` / `PIRE0_EL1` nibbles. `_O`: the permission overlay applies.
pub const PIE_NONE_O: u64 = 0x0;
pub const PIE_R_O: u64 = 0x1;
pub const PIE_X_O: u64 = 0x2;
pub const PIE_RX_O: u64 = 0x3;
pub const PIE_RW_O: u64 = 0x5;
pub const PIE_RWX_O: u64 = 0x7;
pub const PIE_R: u64 = 0x8;
/// Read, and GCS read and write: a plain store is refused. Defined with
/// FEAT_GCS only (reserved without it); Linux installs it on every S1PIE core
/// (pgtable-prot.h `PIE_E0`), and so does [`PIR_EL1_VALUE`].
pub const PIE_GCS: u64 = 0x9;
pub const PIE_RX: u64 = 0xa;
pub const PIE_RW: u64 = 0xc;
pub const PIE_RWX: u64 = 0xe;

/// The kernel GCS page's index: PXN alone (no UXN, DBM or AP\[1\]), one the
/// page-table code never produces.
pub const GCS_INDEX: usize = 0b0100;

/// `TCR2_EL1.PIE` (bit 1).
pub const TCR2_EL1_PIE: u64 = 1 << 1;
/// `HFGRTR_EL2` / `HFGWTR_EL2` `nPIR_EL1` (bit 58) and `nPIRE0_EL1` (bit 57):
/// 1 lets EL1 access the register.
pub const HFGXTR_NPIR_EL1: u64 = 1 << 58;
pub const HFGXTR_NPIRE0_EL1: u64 = 1 << 57;

/// Read, write and execute at one exception level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rwx {
    pub r: bool,
    pub w: bool,
    pub x: bool,
}

/// What EL1 and EL0 may do through a leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Access {
    pub el1: Rwx,
    pub el0: Rwx,
}

const fn bit(word: u64, b: u64) -> bool {
    word & b != 0
}

/// The direct permissions of the leaf `word`, `TCR_EL1.HD` and
/// `SCTLR_EL1.WXN` off (DBM ignored): AP\[1\] gives EL0 read, AP\[2\] takes
/// write away at both levels, UXN and PXN take execute away, and EL1 never
/// executes a page EL0 can write.
pub const fn direct(word: u64) -> Access {
    let (user, ro) = (bit(word, AP_EL0), bit(word, AP_RO));
    Access {
        el1: Rwx { r: true, w: !ro, x: !bit(word, PXN) && !(user && !ro) },
        el0: Rwx { r: user, w: user && !ro, x: !bit(word, UXN) },
    }
}

/// Does the page-table code produce index `i`? Kernel leaves carry UXN and no
/// AP\[1\], user leaves PXN and AP\[1\] (`mmu::attr_bits`).
pub const fn produced(i: usize) -> bool {
    let (user, pxn, uxn) = (i & 1 != 0, i & 4 != 0, i & 8 != 0);
    (uxn && !user) || (pxn && user)
}

/// The leaf the page-table code builds for index `i` (writable exactly when
/// DBM is set): what [`direct`] reads to derive the registers.
pub const fn index_leaf(i: usize) -> u64 {
    let mut w = 0;
    let mut k = 0;
    while k < 4 {
        if (i >> k) & 1 != 0 {
            w |= 1 << PI_BITS[k];
        }
        k += 1;
    }
    if w & DBM == 0 { w | AP_RO } else { w }
}

/// The `_O` nibble for `p`, `None` for a combination with no encoding
/// (write without read).
pub const fn encode(p: Rwx) -> Option<u64> {
    match (p.r, p.w, p.x) {
        (false, false, false) => Some(PIE_NONE_O),
        (true, false, false) => Some(PIE_R_O),
        (false, false, true) => Some(PIE_X_O),
        (true, false, true) => Some(PIE_RX_O),
        (true, true, false) => Some(PIE_RW_O),
        (true, true, true) => Some(PIE_RWX_O),
        _ => None,
    }
}

/// A nibble's meaning: `(access, gcs, overlay applies)`; `None` for an
/// encoding this kernel never writes.
pub const fn decode(n: u64) -> Option<(Rwx, bool, bool)> {
    const fn p(r: bool, w: bool, x: bool) -> Rwx {
        Rwx { r, w, x }
    }
    Some(match n {
        PIE_NONE_O => (p(false, false, false), false, true),
        PIE_R_O => (p(true, false, false), false, true),
        PIE_X_O => (p(false, false, true), false, true),
        PIE_RX_O => (p(true, false, true), false, true),
        PIE_RW_O => (p(true, true, false), false, true),
        PIE_RWX_O => (p(true, true, true), false, true),
        PIE_R => (p(true, false, false), false, false),
        PIE_GCS => (p(true, false, false), true, false),
        PIE_RX => (p(true, false, true), false, false),
        PIE_RW => (p(true, true, false), false, false),
        PIE_RWX => (p(true, true, true), false, false),
        _ => return None,
    })
}

/// Nibble `i` of a `PIR_EL1`-format value.
pub const fn nibble(reg: u64, i: usize) -> u64 {
    (reg >> (4 * i)) & 0xF
}

/// `reg` with nibble `i` set to `n`.
pub const fn with_nibble(reg: u64, i: usize, n: u64) -> u64 {
    (reg & !(0xF << (4 * i))) | (n & 0xF) << (4 * i)
}

const fn build(el1: bool) -> u64 {
    let mut v = 0;
    let mut i = 0;
    while i < 16 {
        let n = if produced(i) {
            let a = direct(index_leaf(i));
            match encode(if el1 { a.el1 } else { a.el0 }) {
                Some(n) => n,
                None => panic!("a produced index has no encoding"),
            }
        } else if i == GCS_INDEX && el1 {
            PIE_GCS
        } else {
            PIE_NONE_O
        };
        v = with_nibble(v, i, n);
        i += 1;
    }
    v
}

/// EL1's permissions: the direct meaning of each produced index, the kernel
/// GCS page at [`GCS_INDEX`], nothing elsewhere.
pub const PIR_EL1_VALUE: u64 = build(true);
/// EL0's: the direct meaning of each produced index (kernel ones grant
/// nothing), nothing elsewhere; the GCS page is EL1's only.
pub const PIRE0_EL1_VALUE: u64 = build(false);
const _: () = assert!(!produced(GCS_INDEX));

/// What the leaf `word` grants with PIE on, `pir` / `pire0` installed and
/// `TCR_EL1.HD` off. `ndirty_removes_write`: whether bit 7 takes write away
/// (the premise the module doc says no produced word depends on).
pub const fn indirect(word: u64, pir: u64, pire0: u64, ndirty_removes_write: bool) -> Option<Access> {
    let i = pi_index(word);
    let (Some((mut el1, ..)), Some((mut el0, ..))) = (decode(nibble(pir, i)), decode(nibble(pire0, i))) else {
        return None;
    };
    if ndirty_removes_write && bit(word, AP_RO) {
        el1.w = false;
        el0.w = false;
    }
    Some(Access { el1, el0 })
}

/// The kernel GCS leaf made from `rw`, a kernel read-write leaf: index
/// [`GCS_INDEX`] (PXN set; UXN, DBM, AP\[1\] and AP\[2\] clear), every other
/// bit as it was.
pub const fn gcs_leaf(rw: u64) -> u64 {
    (rw & !(UXN | DBM | AP_EL0 | AP_RO)) | PXN
}

/// `TCR2_EL1` whole: POE (`ptwin`) and PIE as asked, every other field 0
/// (they are UNKNOWN out of reset and change what a descriptor means).
pub const fn tcr2_value(poe: bool, pie: bool) -> u64 {
    (if poe { super::ptwin::TCR2_EL1_POE } else { 0 }) | if pie { TCR2_EL1_PIE } else { 0 }
}

/// The boot CPU turned PIE on: every other CPU must, or stop.
static ON: AtomicBool = AtomicBool::new(false);
/// The `PIR_EL1` the boot CPU installed ([`PIR_EL1_VALUE`] but under a gate
/// canary), for every other CPU.
static PIR_LIVE: AtomicU64 = AtomicU64::new(PIR_EL1_VALUE);

/// Whether this boot runs with indirect permissions (the boot CPU's readback).
pub fn on() -> bool {
    ON.load(Ordering::Acquire)
}

/// The `PIR_EL1` every CPU installs.
pub fn pir_live() -> u64 {
    PIR_LIVE.load(Ordering::Relaxed)
}

/// Does the build ask for PIE and the CPU have it (and FEAT_TCR2)?
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn wanted() -> bool {
    let regs = crate::cpu::features::read_id_regs();
    azos_arch_api::isa::aarch64::S1PIE.gate(regs.s1pie() && regs.tcr2())
}

/// This CPU's one `TCR2_EL1` write: `PIRE0_EL1` and `PIR_EL1` first when `pie`
/// (PIE never takes effect over UNKNOWN registers), then [`tcr2_value`], and a
/// local TLB invalidation so no translation cached under the direct
/// permissions outlives the switch. `POR_EL1` is the caller's, before this.
///
/// # Safety
/// EL1, FEAT_TCR2 present, EL2 granted the registers; FEAT_S1POE when `poe`,
/// FEAT_S1PIE when `pie`; the live tables are the page-table code's
/// ([`produced`] indices only), not the boot identity map.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn write_tcr2(poe: bool, pie: bool) {
    // SAFETY: the caller's contract above.
    unsafe {
        if pie {
            core::arch::asm!(
                "msr S3_0_C10_C2_2, {e0}", // PIRE0_EL1
                "msr S3_0_C10_C2_3, {e1}", // PIR_EL1
                e0 = in(reg) PIRE0_EL1_VALUE, e1 = in(reg) pir_live(),
                options(nomem, nostack, preserves_flags),
            );
        }
        core::arch::asm!("msr S3_0_C2_C0_3, {t}", "isb", t = in(reg) tcr2_value(poe, pie), options(nostack));
        if pie {
            core::arch::asm!("tlbi vmalle1", "dsb nsh", "isb", options(nostack, preserves_flags));
        }
    }
}

/// `(TCR2_EL1, PIR_EL1, PIRE0_EL1)` of this CPU. Only where FEAT_S1PIE is
/// present and granted.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn read_this_cpu() -> (u64, u64, u64) {
    let (t, p, e): (u64, u64, u64);
    // SAFETY: reads of registers the caller's probe says exist.
    unsafe {
        core::arch::asm!("mrs {0}, S3_0_C2_C0_3", "mrs {1}, S3_0_C10_C2_3", "mrs {2}, S3_0_C10_C2_2",
            out(reg) t, out(reg) p, out(reg) e, options(nomem, nostack, preserves_flags));
    }
    (t, p, e)
}

/// Is PIE on here with the registers every CPU installs?
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn active_this_cpu() -> bool {
    let (t, p, e) = read_this_cpu();
    t & TCR2_EL1_PIE != 0 && p == pir_live() && e == PIRE0_EL1_VALUE
}

/// The boot CPU, once its real tables are installed and before any other CPU
/// runs: PIE on with `pir` ([`PIR_EL1_VALUE`] but under a gate canary) when
/// [`wanted`]; true when it read back on, and then every CPU follows
/// ([`on`]). POE is not on yet: the pool locks later, through `ptwin`.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn enable_boot_cpu(pir: u64) -> bool {
    if !wanted() {
        return false;
    }
    PIR_LIVE.store(pir, Ordering::Relaxed);
    // SAFETY: `wanted` probed FEAT_S1PIE and FEAT_TCR2; the trampoline granted
    // the registers on such a core; the caller runs on the kernel's tables.
    unsafe { write_tcr2(false, true) };
    let ok = active_this_cpu();
    ON.store(ok, Ordering::Release);
    ok
}
