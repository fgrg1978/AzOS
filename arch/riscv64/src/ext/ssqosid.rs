// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Ssqosid: the `srmcfg` CSR, a resource-partition tag on every memory
//! request the hart issues (Kconfig `RV_SSQOSID`).
//!
//! `srmcfg` (0x181) holds two fields: RCID (bits 11:0), the resource control
//! id a CBQRI cache-capacity or memory-bandwidth controller apportions by, and
//! MCID (bits 27:16), the monitoring id its counters group by. Both widths are
//! implementation-defined (up to 12 bits). The kernel writes the same number
//! to both: the Domain's `partition_id` (`azos_sched::qos`, on a context
//! switch), so a partition's share and its measured use are one id.
//!
//! Two steps, the shape H and Zkr use ([`super::hv::probe`], `seed.rs`):
//! cpu@0's device tree declares `ssqosid` (`DtbInfo::isa_ssqosid`), then one
//! trap-safe write of ones to both fields and a read-back under a private
//! `stvec`. The read-back is the Linux `vmid` method: the fields are WARL, so
//! the bits that stick are the implemented width. The device tree alone is not
//! trusted (Smstateen or the firmware may withhold the CSR from S-mode, and
//! the access then traps). The old value is written back, so the probe
//! changes nothing.
//!
//! **A partition id that does not fit is refused, never masked.** RCID wider
//! than the hardware field would alias another partition's share: the tag is
//! then not written ([`set_tag`] answers `false`) and the caller keeps the
//! default partition (`azos_sched::domain::set_partition`). A partition id
//! that fits RCID but not MCID keeps its RCID and is monitored under MCID 0:
//! isolation is the property, counting is not.
//!
//! The decision is made once on the boot hart; the harts of one machine are
//! taken to be uniform (as `riscv,isa` of cpu@0 stands for all of them).

use core::sync::atomic::{AtomicU16, Ordering};

/// The CSR number.
pub const SRMCFG: u16 = 0x181;

/// Width of each field's mask, at most (RCID: 11:0, MCID: 27:16).
const FIELD_MASK: usize = 0xFFF;
const MCID_SHIFT: usize = 16;

/// Highest RCID this hart implements; 0 = not in use (the boot did not
/// select it, or only RCID 0 exists).
static RCID_MAX: AtomicU16 = AtomicU16::new(0);
/// Highest MCID this hart implements.
static MCID_MAX: AtomicU16 = AtomicU16::new(0);

/// The implemented field masks from the read-back of `srmcfg` after ones were
/// written to both fields: `(rcid_max, mcid_max)`. A field whose bits are not
/// one run from bit 0 (a read-back no sane WARL field gives) reads as absent,
/// `0`: it is not a width to trust.
pub const fn widths_from_readback(readback: usize) -> (u16, u16) {
    (run_from_zero(readback & FIELD_MASK), run_from_zero((readback >> MCID_SHIFT) & FIELD_MASK))
}

/// `m` when it is `2^k - 1` (the all-ones run from bit 0, possibly empty), else `0`.
const fn run_from_zero(m: usize) -> u16 {
    if m & (m + 1) == 0 { m as u16 } else { 0 }
}

/// The `srmcfg` word for `partition` on a hart with the given field maxima:
/// RCID and MCID both `partition`, except that MCID falls back to 0 when it
/// does not fit. `None` when `partition` does not fit RCID.
pub const fn word(partition: u16, rcid_max: u16, mcid_max: u16) -> Option<usize> {
    if partition > rcid_max {
        return None;
    }
    let mcid = if partition <= mcid_max { partition } else { 0 };
    Some(((mcid as usize) << MCID_SHIFT) | partition as usize)
}

/// Decide Ssqosid on the boot hart: the Kconfig policy allows it, cpu@0
/// declares `ssqosid`, and the execution probe confirms (run only then, so
/// `n` and an undeclared token execute nothing). `probe` returns the
/// read-back of [`SRMCFG`] after ones were written to both fields, or `None`
/// when the access trapped. Returns the decision.
pub fn select(policy_allows: bool, dt_declares: bool, probe: impl FnOnce() -> Option<usize>) -> bool {
    let (rcid, mcid) = if policy_allows && dt_declares {
        probe().map_or((0, 0), widths_from_readback)
    } else {
        (0, 0)
    };
    RCID_MAX.store(rcid, Ordering::Release);
    MCID_MAX.store(mcid, Ordering::Release);
    available()
}

/// Is Ssqosid in use on this boot: the probe passed and the hart implements
/// at least one RCID beyond the default?
#[inline]
pub fn available() -> bool {
    max_partition() != 0
}

/// The highest partition id [`set_tag`] accepts; 0: Ssqosid is not in use.
#[inline(always)]
pub fn max_partition() -> u16 {
    RCID_MAX.load(Ordering::Relaxed)
}

/// Write `partition` as this hart's tag. `false`, nothing written, when it
/// does not fit RCID (or Ssqosid is not in use).
#[inline]
pub fn set_tag(partition: u16) -> bool {
    let rcid_max = RCID_MAX.load(Ordering::Relaxed);
    if rcid_max == 0 {
        return false;
    }
    match word(partition, rcid_max, MCID_MAX.load(Ordering::Relaxed)) {
        Some(w) => {
            write(w);
            true
        }
        None => false,
    }
}

#[inline(always)]
fn write(w: usize) {
    #[cfg(target_arch = "riscv64")]
    // SAFETY: only reached after the boot probe accessed `srmcfg` without a
    // trap; the CSR touches no memory and no other CSR.
    unsafe {
        core::arch::asm!("csrw {csr}, {w}", csr = const SRMCFG, w = in(reg) w, options(nomem, nostack));
    }
    #[cfg(not(target_arch = "riscv64"))]
    let _ = w;
}

/// One trap-safe run of the probe: write ones to RCID and MCID, read back,
/// restore the old value. `None`: the access trapped.
pub fn trap_probe() -> Option<usize> {
    #[cfg(target_arch = "riscv64")]
    {
        // SAFETY: the routine installs its own stvec with interrupts off and
        // restores both; `srmcfg` is written back unchanged; no memory.
        let r = unsafe { azos_ssqosid_probe() };
        (r.ok != 0).then_some(r.value)
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        None
    }
}

/// `azos_ssqosid_probe`'s two return registers (a0, a1).
#[cfg(target_arch = "riscv64")]
#[repr(C)]
struct ProbeRead {
    ok: usize,
    value: usize,
}

// `azos_ssqosid_probe() -> (a0 = 1 read / 0 trapped, a1 = srmcfg after ones)`.
// The `seed.rs` probe's shape: sstatus.SIE cleared, a private stvec whose
// handler zeroes a0 and resumes after the access, stvec and SIE restored.
// Clobbers t0-t4 (caller-saved).
#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".pushsection .text.azos_ssqosid_probe, \"ax\"",
    ".globl azos_ssqosid_probe",
    ".p2align 2",
    "azos_ssqosid_probe:",
    "    csrrci t3, sstatus, 2",
    "    csrr   t1, stvec",
    "    la     t0, 1f",
    "    csrw   stvec, t0",
    "    li     a0, 1",
    "    li     a1, 0",
    "    li     t2, 0x0FFF0FFF",
    "    csrrw  t4, {csr}, t2",
    "    csrrw  a1, {csr}, t4",
    "2:",
    "    csrw   stvec, t1",
    "    andi   t3, t3, 2",
    "    csrs   sstatus, t3",
    "    ret",
    ".p2align 2",
    "1:",
    "    li     a0, 0",
    "    la     t0, 2b",
    "    csrw   sepc, t0",
    "    sret",
    ".popsection",
    csr = const SRMCFG,
);

#[cfg(target_arch = "riscv64")]
unsafe extern "C" {
    fn azos_ssqosid_probe() -> ProbeRead;
}
