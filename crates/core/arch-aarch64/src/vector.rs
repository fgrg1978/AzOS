// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! NEON-backed Vector implementations.
//!
//! ARMv8-A makes Advanced SIMD (NEON) mandatory — every PE that
//! executes aarch64 instructions supports it. That's the
//! opposite of x86 (AVX is optional) and RISC-V (V is optional);
//! no runtime probe is needed.
//!
//! Scope today: just `dot_f32`, which the kernel's ML inner
//! loops use. SVE / SVE2 (variable-length vectors) is a B1.sve
//! follow-up — it offers larger throughput on Cortex-A510 /
//! Neoverse-V1 but requires runtime detection and is not on
//! Cortex-A72 (the QEMU virt default).
//!
//! **Seam note:** this file is also pulled directly via `#[path]` into
//! `tests/host/arch-api-tests` (see that crate's `aarch64_vector` module doc)
//! so its NEON kernels run as host tests on this project's Apple Silicon
//! dev machines. A `use crate::…` added here that isn't satisfied by that
//! test crate's own root will break that seam: add the matching entry
//! there too.

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
use core::arch::aarch64::{vaddvq_f32, vdupq_n_f32, vfmaq_f32, vld1q_f32};

// **The kernel does not get this path.** The aarch64 kernel is built for
// `aarch64-unknown-none-softfloat` (FP-free, like Linux: user FP state is
// saved lazily, see `kernel/src/entry/aarch64/fp_lazy.rs`), where
// `target_feature = "neon"` is off, so `dot_f32_best` below resolves to
// `dot_f32_scalar` and compiles to integer code plus soft-float calls. The
// NEON kernel stays compiled wherever NEON is part of the target: the
// hard-float `aarch64-unknown-none` build of this crate and its host tests
// (`tests/host/arch-api-tests`, Apple Silicon).

/// NEON-accelerated f32 dot product. Loads 4 lanes at a time
/// via VLD1, accumulates via VFMA (fused multiply-add), and
/// horizontally sums via VADDVQ. Tail elements (< 4 left) get
/// scalar treatment.
///
/// # Safety
///
/// The NEON intrinsics below are unsafe, so this is an `unsafe fn`.
///
/// **No `#[target_feature(enable = "neon")]`.** It used to carry one, and
/// rustc warns that enabling `neon` is *unsound* on a soft-float target
/// (it changes the ABI) and will reject it outright in a future release.
/// The fix is the target, not the attribute: this crate builds for
/// `aarch64-unknown-none` (hard float), where NEON is on by default — it is
/// mandatory from ARMv8.0 and the baseline here is ARMv8.5. The attribute is
/// also the thing that de-inlines a function, which cost the RISC-V side a
/// measured 325 → 357 instructions on the syscall floor (2026-09-17).
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
pub unsafe fn dot_f32_neon(a: &[f32], b: &[f32]) -> f32 {
    debug_assert_eq!(
        a.len(),
        b.len(),
        "dot_f32_neon: input slice lengths differ",
    );
    let n = a.len().min(b.len());
    let chunks = n / 4;
    let tail = n - chunks * 4;

    unsafe {
        let mut acc = vdupq_n_f32(0.0);
        let mut ap = a.as_ptr();
        let mut bp = b.as_ptr();
        for _ in 0..chunks {
            let va = vld1q_f32(ap);
            let vb = vld1q_f32(bp);
            acc = vfmaq_f32(acc, va, vb);
            ap = ap.add(4);
            bp = bp.add(4);
        }
        let mut sum = vaddvq_f32(acc);
        // Handle tail (0..=3 elements).
        for i in 0..tail {
            sum += *ap.add(i) * *bp.add(i);
        }
        sum
    }
}

/// Scalar fallback. Kept compiled even on aarch64 so tests +
/// auditors can compare numeric results between the SIMD and
/// scalar paths (the two should agree bit-for-bit modulo FP
/// associativity — the SIMD form accumulates in a different
/// order, so the result CAN drift by ~1 ULP for long inputs).
pub fn dot_f32_scalar(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len().min(b.len());
    let mut acc: f32 = 0.0;
    for i in 0..n {
        acc += a[i] * b[i];
    }
    acc
}

// ── SVE detection (ID_AA64PFR0_EL1.SVE bits [35:32]) ─────────
//
// Symmetric to x86_64::vector's CPUID-based AVX detection. SVE
// (Scalable Vector Extension) is optional in ARMv8.2+ and isn't
// present on Cortex-A72 (the QEMU virt default), so the current
// dispatcher always falls back to NEON. The detection +
// `dot_f32_best` shim are in place so:
//
//   1. The kernel can already query "what's the widest path?"
//      and surface it through procfs (mirror of `active_backend`
//      on the x86_64 side).
//   2. When we eventually run on a Neoverse / Cortex-X core
//      with SVE, plugging in a real `dot_f32_sve` is a one-
//      function add — the dispatcher already exists.

/// Read ID_AA64PFR0_EL1 and return true iff the SVE field
/// (bits [35:32]) is non-zero. Caches the answer in a static so
/// subsequent calls are a single atomic load.
#[cfg(target_arch = "aarch64")]
pub fn has_sve() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering};
    /// 0 = unprobed, 1 = no SVE, 2 = SVE present.
    static CACHE: AtomicU8 = AtomicU8::new(0);
    match CACHE.load(Ordering::Acquire) {
        1 => false,
        2 => true,
        _ => {
            let pfr0: u64;
            unsafe {
                core::arch::asm!(
                    "mrs {0}, ID_AA64PFR0_EL1",
                    out(reg) pfr0,
                    options(nomem, nostack, preserves_flags),
                );
            }
            let sve_field = (pfr0 >> 32) & 0xF;
            let v = if sve_field != 0 { 2 } else { 1 };
            CACHE.store(v, Ordering::Release);
            v == 2
        }
    }
}

/// Dispatcher used by `api_impl::Vector::dot_f32`. SVE path is
/// not implemented yet (no test hardware) so this always falls
/// back to NEON; the structure mirrors the x86_64 AVX shim so
/// the migration story is uniform across the two arches.
#[cfg(target_arch = "aarch64")]
pub fn dot_f32_best(a: &[f32], b: &[f32]) -> f32 {
    // SVE path lives here once we have Cortex-X / Neoverse:
    //   if has_sve() { unsafe { dot_f32_sve(a, b) } } else { … }
    let _ = has_sve(); // prime the cache for `active_backend`
    #[cfg(target_feature = "neon")]
    {
        unsafe { dot_f32_neon(a, b) }
    }
    #[cfg(not(target_feature = "neon"))]
    {
        dot_f32_scalar(a, b)
    }
}

/// Diagnostic accessor — what backend `dot_f32_best` will pick
/// today. Will return "sve" once a real impl lands.
#[cfg(target_arch = "aarch64")]
pub fn active_backend() -> &'static str {
    if !cfg!(target_feature = "neon") {
        "scalar (soft-float build)"
    } else if has_sve() {
        "neon (sve detected but no impl yet)"
    } else {
        "neon"
    }
}
