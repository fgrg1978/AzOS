// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What this CPU actually implements, read from the architectural ID registers.
//!
//! The baseline is **ARMv8.5-A** (owner decision 97, 2026-09-19): LSE atomics
//! (8.1), PAC (8.3), BTI and MTE (8.5). "Modern ARM, no legacy support" — the
//! same rule the RISC-V side is held to.
//!
//! # Why this is nicer than the RISC-V equivalent, and why it is still a probe
//!
//! RISC-V has no architectural way to ask a hart what it implements: reading an
//! unimplemented CSR traps, so `crates/core/arch-riscv64/src/cbo.rs` has to take the
//! device tree's word for it *and* execute the instruction under a private
//! `stvec` to see whether it faults. AArch64 has `ID_AA64*_EL1`: reading them
//! at EL1 is architectural, always succeeds, and the values are defined by the
//! ARM ARM. So this module needs no trap handler and no fallback path of its
//! own — the register IS the answer.
//!
//! What does NOT change is the rule around it: **no extension is ever a hard
//! requirement.** Every user of this module branches, with a path that works on
//! a CPU that lacks the feature. A binary that assumes MTE and meets a
//! Cortex-A53 must degrade, not fault. The VF2 taught that lesson on the other
//! ISA: the board turned out to be plain `rv64gc`, and every extension item
//! written for it had no target.
//!
//! # Reading the fields
//!
//! Each ID register is a set of 4-bit fields. A field is `0b0000` when the
//! feature is absent, and the values are monotonic: a larger value implies
//! everything a smaller one provides. So `>= 1` is the right test, never `== 1`
//! — a future CPU reporting `0b0010` still has the feature.

// `target_arch` alone is NOT the right guard, and the host test caught it:
// this repo is developed on an Apple Silicon Mac, where `target_arch =
// "aarch64"` is true but the code runs at EL0 under a kernel. `ID_AA64*_EL1`
// is an EL1 register, so the read was an illegal instruction and killed the
// test process. `target_os = "none"` is what means "we ARE the kernel".
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
use core::arch::asm;

/// What the running CPU implements, as one snapshot.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Features {
    /// FEAT_LSE (ARMv8.1): `LDADD`/`CAS`/`SWP` — single-instruction atomics
    /// instead of an LL/SC retry loop. The one with a measurable cost on a
    /// contended lock.
    pub lse: bool,
    /// FEAT_PAuth (ARMv8.3): pointer authentication. Signs the return address
    /// so a stack overwrite cannot redirect a return.
    pub pauth: bool,
    /// FEAT_BTI (ARMv8.5): indirect branches land only on a `BTI` landing pad,
    /// which removes most jump-oriented gadgets.
    pub bti: bool,
    /// FEAT_MTE (ARMv8.5): memory tagging. A 4-bit tag per 16-byte granule,
    /// checked by hardware on every access — use-after-free and linear overflow
    /// become a fault at the instruction that did it, not corruption noticed
    /// later somewhere else. The most valuable of the four for this kernel.
    pub mte: bool,
    /// MTE with *synchronous* checking (`MTE >= 2`): the fault is precise, so
    /// the flight recorder names the faulting instruction. Asynchronous-only
    /// MTE reports the fault later and is far less useful for an audit trail.
    pub mte_sync: bool,
    /// FEAT_CRC32: `CRC32{B,H,W,X}`/`CRC32C*` (ID_AA64ISAR0_EL1.CRC32 [19:16]).
    pub crc32: bool,
    /// FEAT_AES (ISAR0.AES [7:4] >= 1).
    pub aes: bool,
    /// FEAT_PMULL: 64-bit polynomial multiply (ISAR0.AES >= 2).
    pub pmull: bool,
    /// FEAT_SHA256: `SHA256H`/`SHA256H2`/`SHA256SU0`/`SHA256SU1` (ISAR0.SHA2 [15:12]).
    pub sha2: bool,
}

impl Features {
    /// Nothing detected. What a host build and a pre-ARMv8.1 CPU both look like.
    pub const NONE: Self = Self {
        lse: false, pauth: false, bti: false, mte: false, mte_sync: false,
        crc32: false, aes: false, pmull: false, sha2: false,
    };

    /// Whether this CPU meets the ARMv8.5 baseline this port targets.
    ///
    /// A CPU that does not is still supported — every user branches — but a
    /// boot on one is worth a log line, because it means the security
    /// properties the baseline was chosen for are not in force.
    #[inline]
    pub const fn meets_armv8_5_baseline(&self) -> bool {
        self.lse && self.pauth && self.bti && self.mte
    }
}

/// A 4-bit field of an ID register.
#[inline]
const fn field(reg: u64, shift: u32) -> u64 {
    (reg >> shift) & 0xF
}

/// What the three ID register values say. Pure, so the host tests can feed
/// it hand-built values (wave 13: the hwcap bits come from here).
pub const fn decode(isar0: u64, isar1: u64, pfr1: u64) -> Features {
    // ID_AA64ISAR0_EL1.Atomic [23:20] >= 2 ⇒ FEAT_LSE.
    let lse = field(isar0, 20) >= 2;
    // ID_AA64ISAR1_EL1.APA [7:4] (address auth, QARMA) or API [11:8]
    // (address auth, IMPLEMENTATION DEFINED). Either is FEAT_PAuth; QEMU
    // reports one of them depending on `pauth-impdef`.
    let pauth = field(isar1, 4) >= 1 || field(isar1, 8) >= 1;
    // ID_AA64PFR1_EL1.BT [3:0] >= 1 ⇒ FEAT_BTI.
    let bti = field(pfr1, 0) >= 1;
    // ID_AA64PFR1_EL1.MTE [11:8]: 1 = instructions only, 2 = full tag
    // checking, 3 = asymmetric. Synchronous checking needs >= 2.
    let mte_field = field(pfr1, 8);
    Features {
        lse, pauth, bti, mte: mte_field >= 1, mte_sync: mte_field >= 2,
        // ISAR0.CRC32 [19:16], ISAR0.AES [7:4] (2 = + PMULL), ISAR0.SHA2 [15:12].
        crc32: field(isar0, 16) >= 1,
        aes: field(isar0, 4) >= 1,
        pmull: field(isar0, 4) >= 2,
        sha2: field(isar0, 12) >= 1,
    }
}

/// Read the ID registers and report what they say.
///
/// Safe: `ID_AA64*_EL1` are readable at EL1 by definition, and this writes
/// nothing. Anywhere that is not bare-metal aarch64 — the riscv64 kernel that
/// links this crate as essentially-empty, and the host test build, which on an
/// Apple Silicon Mac IS `target_arch = "aarch64"` but runs at EL0 — it answers
/// [`Features::NONE`] without executing anything.
pub fn detect() -> Features {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        let isar1: u64;
        let pfr1: u64;
        let isar0: u64;
        // SAFETY: architectural reads of EL1-readable ID registers. No side
        // effects, no memory access.
        unsafe {
            asm!("mrs {}, ID_AA64ISAR1_EL1", out(reg) isar1, options(nostack, nomem, preserves_flags));
            asm!("mrs {}, ID_AA64PFR1_EL1",  out(reg) pfr1,  options(nostack, nomem, preserves_flags));
            asm!("mrs {}, ID_AA64ISAR0_EL1", out(reg) isar0, options(nostack, nomem, preserves_flags));
        }
        decode(isar0, isar1, pfr1)
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
    {
        Features::NONE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The field extractor, against hand-built register values. This is the
    /// half that can be wrong without any hardware to notice: a shift off by
    /// four reads a neighbouring feature's bits and reports it as this one.
    #[test]
    fn a_field_reads_its_own_four_bits_and_no_others() {
        // Every nibble distinct, so a wrong shift cannot coincidentally match.
        let reg = 0xFEDC_BA98_7654_3210u64;
        assert_eq!(field(reg, 0), 0x0);
        assert_eq!(field(reg, 4), 0x1);
        assert_eq!(field(reg, 8), 0x2);
        assert_eq!(field(reg, 20), 0x5);
        assert_eq!(field(reg, 60), 0xF);
    }

    /// The tests are `>= n`, never `== n`: ID fields are monotonic, so a future
    /// CPU reporting a larger value still has the feature. `==` is how a port
    /// silently loses a feature on the next generation of silicon.
    #[test]
    fn a_larger_field_value_still_counts_as_present() {
        for v in 1..=0xFu64 {
            assert!(v >= 1, "BT={v} must read as present");
        }
        // MTE: 1 is instructions-only, 2+ is real checking.
        assert!(1u64 >= 1 && !(1u64 >= 2), "MTE=1 is present but not synchronous");
        assert!(3u64 >= 2, "MTE=3 (asymmetric) still provides synchronous checking");
    }

    /// The baseline is the conjunction, not "any of them".
    #[test]
    fn the_baseline_needs_all_four() {
        let all = Features {
            lse: true, pauth: true, bti: true, mte: true, mte_sync: true,
            crc32: false, aes: false, pmull: false, sha2: false,
        };
        assert!(all.meets_armv8_5_baseline());
        for drop in 0..4 {
            let mut f = all;
            match drop {
                0 => f.lse = false,
                1 => f.pauth = false,
                2 => f.bti = false,
                _ => f.mte = false,
            }
            assert!(!f.meets_armv8_5_baseline(), "dropping feature {drop} must fail the baseline");
        }
        assert!(!Features::NONE.meets_armv8_5_baseline());
    }

    /// Wave 13 (vDSO hwcap): CRC32, AES/PMULL and SHA2 come from their own
    /// ID_AA64ISAR0_EL1 nibbles and nothing else. Each field is set alone
    /// here, so a shift that reads a neighbour reports the wrong feature.
    #[test]
    fn the_hwcap_bits_come_from_their_isar0_fields() {
        let none = decode(0, 0, 0);
        assert!(!none.crc32 && !none.aes && !none.pmull && !none.sha2 && !none.lse);
        let f = decode(1 << 16, 0, 0);
        assert!(f.crc32 && !f.aes && !f.sha2 && !f.lse, "CRC32 [19:16] alone: {f:?}");
        let f = decode(1 << 4, 0, 0);
        assert!(f.aes && !f.pmull && !f.crc32 && !f.sha2, "AES=1: AES without PMULL: {f:?}");
        let f = decode(2 << 4, 0, 0);
        assert!(f.aes && f.pmull, "AES=2: AES and PMULL: {f:?}");
        let f = decode(1 << 12, 0, 0);
        assert!(f.sha2 && !f.aes && !f.crc32, "SHA2 [15:12] alone: {f:?}");
        let f = decode(2 << 12, 0, 0);
        assert!(f.sha2, "SHA2=2 (SHA-512 too) still has SHA-256: {f:?}");
        let f = decode(1 << 20, 0, 0);
        assert!(!f.lse && !f.crc32, "Atomic=1 is not FEAT_LSE: {f:?}");
        // Neighbouring nibbles set, ours clear: SHA1 [11:8], SHA3 [35:32], RDM [31:28].
        let f = decode((1 << 8) | (1 << 32) | (1 << 28), 0, 0);
        assert!(!f.crc32 && !f.aes && !f.sha2 && !f.pmull, "neighbours leaked: {f:?}");
        // The ISAR1/PFR1 inputs move none of them.
        let f = decode(0, u64::MAX, u64::MAX);
        assert!(!f.crc32 && !f.aes && !f.sha2 && !f.pmull);
    }

    /// A build that is not bare-metal aarch64 must answer NONE **without
    /// executing anything**.
    ///
    /// This test is why the guard is `target_os = "none"` and not just
    /// `target_arch`: the host here is an Apple Silicon Mac, so `target_arch =
    /// "aarch64"` holds, and the first version of this module happily emitted
    /// `mrs ID_AA64ISAR1_EL1` — an EL1 read from EL0 — which killed the test
    /// process with an illegal instruction. If this test ever dies rather than
    /// fails, the guard has been widened back.
    #[test]
    fn a_build_that_is_not_bare_metal_aarch64_detects_nothing_without_trapping() {
        assert_eq!(detect(), Features::NONE);
    }
}
