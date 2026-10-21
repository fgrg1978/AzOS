// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `RDSEED`, else `RDRAND`, as the boot entropy pool's CPU seed source
//! (`azos_arch_api::entropy`, `ArchPlatform::cpu_seed`).
//!
//! RDSEED returns conditioned entropy straight from the source (NIST SP
//! 800-90B/C), so it is preferred; RDRAND is the output of a DRBG the
//! hardware reseeds, the fallback when RDSEED is absent or Kconfig
//! X86_RDSEED is `n`. Either reports "no data" with CF=0 and is retried
//! within `ENTROPY_CPU_RETRIES`, with PAUSE between tries.
//!
//! The probe is CPUID (`features::detect`); the kernel resolves Kconfig
//! X86_RDSEED / X86_RDRAND against it and calls [`select`] once, on the
//! boot CPU, from `cpu_features`, before `install_entropy` reads. The
//! instructions are written as mnemonics in local `asm!`, not enabled as
//! target features, so nothing else is compiled to assume them.

use azos_arch_api::entropy::{self, CpuSeed, Draw};
use core::sync::atomic::{AtomicU8, Ordering};

const NONE: u8 = 0;
const RDSEED: u8 = 1;
const RDRAND: u8 = 2;

static SOURCE: AtomicU8 = AtomicU8::new(NONE);

/// Pick the source from the policy-gated CPUID answers: RDSEED when
/// `rdseed`, else RDRAND when `rdrand`, else none. Returns whether one was
/// selected (the riscv64/aarch64 `select` shape).
pub fn select(rdseed: bool, rdrand: bool) -> bool {
    let s = if rdseed { RDSEED } else if rdrand { RDRAND } else { NONE };
    SOURCE.store(s, Ordering::Release);
    s != NONE
}

const fn name(s: u8) -> &'static str {
    match s {
        RDSEED => "rdseed",
        RDRAND => "rdrand",
        _ => "none",
    }
}

/// Fill `out` from the selected instruction, or [`CpuSeed::NONE`].
pub fn fill(out: &mut [u8]) -> CpuSeed {
    let s = SOURCE.load(Ordering::Acquire);
    let draw: fn() -> Draw = match s {
        RDSEED => rdseed,
        RDRAND => rdrand,
        _ => return CpuSeed::NONE,
    };
    let bytes = entropy::fill(out, entropy::RETRIES, draw, core::hint::spin_loop);
    CpuSeed { bytes, source: name(s) }
}

/// One instruction, CF into a byte: 8 bytes, or a retry when CF=0.
macro_rules! draw64 {
    ($insn:literal) => {{
        #[cfg(target_arch = "x86_64")]
        {
            let (v, ok): (u64, u8);
            // SAFETY: only reached after `select` saw the instruction in
            // CPUID. Writes RFLAGS (no `preserves_flags`); not `pure`, so
            // every call reads anew.
            unsafe {
                core::arch::asm!(
                    concat!($insn, " {v}"),
                    "setc {ok}",
                    v = out(reg) v, ok = out(reg_byte) ok,
                    options(nostack, nomem),
                );
            }
            if ok != 0 { Draw::Bytes { word: v, len: 8 } } else { Draw::Retry }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Draw::Dead
        }
    }};
}

fn rdseed() -> Draw {
    draw64!("rdseed")
}

fn rdrand() -> Draw {
    draw64!("rdrand")
}
