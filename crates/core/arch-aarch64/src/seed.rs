// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! FEAT_RNG `RNDRRS` as the boot entropy pool's CPU seed source
//! (`azos_arch_api::entropy`, `ArchPlatform::cpu_seed`).
//!
//! `RNDRRS` (`S3_3_C2_C4_1`) reseeds its DRBG from the true entropy source
//! before each read, so each 64-bit value is as close to conditioned
//! entropy as the architecture offers; `RNDR` (`S3_3_C2_C4_0`) would be DRBG
//! output between reseeds. A read that returns no data sets NZCV to 0b0100
//! (Z=1) and the value 0; it is retried within `ENTROPY_CPU_RETRIES`.
//!
//! The probe is the ID register (`features::Features::rng`), architectural
//! at EL1, so there is no trap path to arm: the kernel resolves Kconfig
//! A64_RNG against it and calls [`select`] once, on the boot CPU, from
//! `cpu_features`, before `install_entropy` reads.

use azos_arch_api::entropy::{self, CpuSeed};
use core::sync::atomic::{AtomicBool, Ordering};

static SELECTED: AtomicBool = AtomicBool::new(false);

/// Use `RNDRRS` from now on when `gated` (the ID register's answer, masked
/// by Kconfig A64_RNG). Returns what was selected.
pub fn select(gated: bool) -> bool {
    SELECTED.store(gated, Ordering::Release);
    gated
}

/// Fill `out` from `RNDRRS`, or [`CpuSeed::NONE`] when [`select`] did not
/// choose it.
pub fn fill(out: &mut [u8]) -> CpuSeed {
    if !SELECTED.load(Ordering::Acquire) {
        return CpuSeed::NONE;
    }
    let bytes = entropy::fill(out, entropy::RETRIES, rndrrs, core::hint::spin_loop);
    CpuSeed { bytes, source: "rndrrs" }
}

/// One `RNDRRS` read: 8 bytes, or a retry when Z is set.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
fn rndrrs() -> entropy::Draw {
    let (v, ok): (u64, u64);
    // SAFETY: only reached after `select` saw FEAT_RNG in ID_AA64ISAR0_EL1,
    // which makes RNDRRS readable at EL1. Writes NZCV (no
    // `preserves_flags`); not `pure`, so every call reads anew.
    unsafe {
        core::arch::asm!(
            "mrs {v}, S3_3_C2_C4_1",
            "cset {ok}, ne",
            v = out(reg) v, ok = out(reg) ok,
            options(nostack, nomem),
        );
    }
    if ok != 0 { entropy::Draw::Bytes { word: v, len: 8 } } else { entropy::Draw::Retry }
}

/// Anywhere that is not bare-metal aarch64 (the host test build on Apple
/// Silicon runs at EL0): never selected in practice, and no instruction.
#[cfg(not(all(target_arch = "aarch64", target_os = "none")))]
fn rndrrs() -> entropy::Draw {
    entropy::Draw::Dead
}
