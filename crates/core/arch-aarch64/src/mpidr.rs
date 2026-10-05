// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! MPIDR_EL1 — Multiprocessor Affinity Register decoder.
//!
//! 64-bit register that identifies *this* PE within the system
//! topology. Layout:
//!
//!   bits [7:0]    Aff0 — innermost level (typically thread / SMT)
//!   bits [15:8]   Aff1 — core within cluster
//!   bits [23:16]  Aff2 — cluster within socket
//!   bit  [24]     MT   — 1 if Aff0 is "thread" rather than "PE"
//!   bits [29:30]  RES0
//!   bit  [30]     U    — 1 if uniprocessor (no other PEs)
//!   bit  [31]     RES1 — always 1
//!   bits [39:32]  Aff3 — outermost (socket / package)
//!
//! Already used implicitly by `aarch64-hello`: the PSCI CPU_ON
//! target argument is "Aff0..3 packed", and the ICC_SGI1R_EL1
//! `TargetList` field lives within `Aff0` of a specific Aff1/2/3
//! cluster. Until this module landed callers were poking the
//! sysreg directly + bit-twiddling on the result.

#![allow(dead_code)]

/// Decoded MPIDR_EL1.
#[derive(Clone, Copy, Debug)]
pub struct Mpidr {
    pub raw: u64,
    /// Innermost affinity level — thread/SMT when `MT == 1`,
    /// PE otherwise.
    pub aff0: u8,
    pub aff1: u8,
    pub aff2: u8,
    pub aff3: u8,
    /// True when Aff0 selects a hardware thread (vs a PE) — set
    /// on big.LITTLE designs with SMT cores.
    pub multi_thread: bool,
    /// True when this is the only PE in the system.
    pub uniprocessor: bool,
}

impl Mpidr {
    /// Build a `target_cpu` argument for PSCI CPU_ON from the
    /// caller's chosen affinity values. Aff0-2 occupy bits
    /// [7:0]/[15:8]/[23:16] and Aff3 jumps to [39:32].
    pub const fn pack_for_psci(aff0: u8, aff1: u8, aff2: u8, aff3: u8) -> u64 {
        (aff0 as u64)
            | ((aff1 as u64) << 8)
            | ((aff2 as u64) << 16)
            | ((aff3 as u64) << 32)
    }

    /// Build an ICC_SGI1R_EL1 value for an SGI targeting the
    /// specific PE matching this MPIDR's Aff1/2/3 cluster.
    /// `intid` is the SGI ID (0..=15).
    ///
    /// Bit layout (ICC_SGI1R_EL1):
    ///   bits [15:0]  TargetList — bit N = PE with Aff0=N
    ///   bits [23:16] Aff1
    ///   bits [27:24] INTID
    ///   bits [39:32] Aff2
    ///   bit  [40]    IRM (1 = all-but-self)
    ///   bits [55:48] Aff3
    ///
    /// **Aff0 must be < 16.** This encoding has no `RS` (Range Selector)
    /// term, so an Aff0 >= 16 silently addresses the wrong PE (its low
    /// nibble, under `RS=0`) instead of the one intended. Every caller in
    /// this tree today has Aff0 < 16 (QEMU virt `-smp 2..4`), which is why
    /// this went unnoticed until [`crate::gic::sgi1r_encode`] added the
    /// `RS` term for the general case — prefer that one for new code;
    /// this method stays for the existing self-targeted call sites.
    pub fn sgi_to_self_aff0(&self, intid: u8) -> u64 {
        let target_list: u64 = 1 << (self.aff0 & 0xF);
        target_list
            | ((self.aff1 as u64) << 16)
            | ((intid as u64 & 0xF) << 24)
            | ((self.aff2 as u64) << 32)
            | ((self.aff3 as u64) << 48)
    }

    /// This PE's affinity packed via [`affinity_key`] — the canonical
    /// `u32` shape [`crate::gic::typer_affinity_key`] and
    /// [`crate::gic::find_redistributor`] use to match a redistributor
    /// frame against an MPIDR without needing the `Mpidr` type itself.
    pub const fn affinity_key(&self) -> u32 {
        affinity_key(self.aff0, self.aff1, self.aff2, self.aff3)
    }
}

/// Pack `Aff0..Aff3` into one `u32`: `Aff3<<24 | Aff2<<16 | Aff1<<8 | Aff0`.
///
/// A free function (not just [`Mpidr::affinity_key`]) so a caller with a
/// raw `GICR_TYPER` value — which carries the SAME four affinity bytes,
/// just at different bit offsets — can pack it into the identical shape
/// via [`crate::gic::typer_affinity_key`] and compare the two with a
/// plain `==`. Neither packer needs the other module's type, which is
/// what lets both be pulled standalone (`#[path]`) into a host test crate
/// without dragging the whole crate graph along.
pub const fn affinity_key(aff0: u8, aff1: u8, aff2: u8, aff3: u8) -> u32 {
    (aff0 as u32) | ((aff1 as u32) << 8) | ((aff2 as u32) << 16) | ((aff3 as u32) << 24)
}

/// Same packing as [`affinity_key`], applied directly to a raw
/// `MPIDR_EL1` value: `Aff0` at bits `[7:0]`, `Aff1` at `[15:8]`, `Aff2`
/// at `[23:16]`, `Aff3` at `[39:32]` — see [`read_mpidr`]'s decode for
/// the same field positions. Bits 24 (MT) and 30 (U) sit BETWEEN Aff2 and
/// Aff3 and must not leak into either field; this pulls each field out by
/// its own mask+shift rather than a single contiguous slice, so they
/// can't.
pub const fn mpidr_affinity_key(raw: u64) -> u32 {
    affinity_key(
        (raw & 0xFF) as u8,
        ((raw >> 8) & 0xFF) as u8,
        ((raw >> 16) & 0xFF) as u8,
        ((raw >> 32) & 0xFF) as u8,
    )
}

/// Read MPIDR_EL1 and decode.
#[cfg(target_arch = "aarch64")]
pub fn read_mpidr() -> Mpidr {
    let raw: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, MPIDR_EL1",
            out(reg) raw,
            options(nomem, nostack, preserves_flags),
        );
    }
    Mpidr {
        raw,
        aff0:        ( raw         & 0xFF) as u8,
        aff1:        ((raw >> 8)   & 0xFF) as u8,
        aff2:        ((raw >> 16)  & 0xFF) as u8,
        aff3:        ((raw >> 32)  & 0xFF) as u8,
        multi_thread: ((raw >> 24) & 1) != 0,
        uniprocessor: ((raw >> 30) & 1) != 0,
    }
}

// ── Host-build stubs ────────────────────────────────────────

#[cfg(not(target_arch = "aarch64"))]
pub fn read_mpidr() -> Mpidr {
    Mpidr {
        raw: 0, aff0: 0, aff1: 0, aff2: 0, aff3: 0,
        multi_thread: false, uniprocessor: false,
    }
}
