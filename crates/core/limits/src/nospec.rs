// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Spectre variant 1 (bounds-check bypass) index masking — the analogue of
//! Linux's `array_index_nospec`.
//!
//! A bounds check is a branch, and a core may run the load after it before
//! the branch resolves. With a mispredicted check and an index from ring 3,
//! that load reads past the table, and a second load whose address depends on
//! the value read leaves a cache footprint ring 3 can time. The fix is to make
//! the index itself, not only the branch, depend on the comparison: the mask
//! below is all-ones when `index < size` and zero otherwise, computed without
//! a branch, so a load under a mispredicted check reads entry 0.
//!
//! - riscv64: `sltu` + `neg`. No conditional instruction whose result could be
//!   predicted, and the sequence is the anchor the disassembly canary looks for.
//! - aarch64: `cmp` + `sbc` + `csdb`, Linux arm64's sequence. Arm permits a
//!   conditional data-processing result to be speculated; `csdb` is the
//!   barrier that stops that (a `hint` that is a NOP on cores without it).
//! - any other target: the portable shift formula, Linux's generic one
//!   (`tests/host/cap-tests` runs the aarch64 sequence on an aarch64 host).
//!
//! Switch: `CONFIG_MITIGATION_SPECTRE_V1_INDEX` (config/Kconfig.mitigations). Off, every
//! function here returns the index unchanged and compiles to nothing.
//!
//! Lives in this crate, next to the switch, because every file that indexes a
//! Kconfig-sized table with a user value already depends on it — the host test
//! crates that `#[path]`-pull those files included.

/// Whether the mask is compiled in (Kconfig `MITIGATION_SPECTRE_V1_INDEX`).
pub const ENABLED: bool = crate::MITIGATION_SPECTRE_V1_INDEX;

/// All-ones when `index < size`, zero otherwise, without a branch.
/// Tested in `tests/host/cap-tests` (`nospec_tests`).
#[inline(always)]
pub fn mask(index: usize, size: usize) -> usize {
    #[cfg(all(target_arch = "riscv64", not(kani)))]
    {
        let m: usize;
        // SAFETY: two ALU instructions on registers; no memory, no stack.
        unsafe {
            core::arch::asm!(
                "sltu {m}, {i}, {s}",
                "neg  {m}, {m}",
                m = out(reg) m, i = in(reg) index, s = in(reg) size,
                options(pure, nomem, nostack, preserves_flags),
            );
        }
        m
    }
    #[cfg(all(target_arch = "aarch64", not(kani)))]
    {
        let m: usize;
        // SAFETY: register-only ALU sequence and a hint; no memory, no stack.
        // Not `pure`: `csdb` is the point and must not be dropped or moved.
        unsafe {
            core::arch::asm!(
                "cmp  {i}, {s}",
                "sbc  {m}, xzr, xzr",
                "csdb",
                m = out(reg) m, i = in(reg) index, s = in(reg) size,
                options(nomem, nostack),
            );
        }
        m
    }
    // Kani cannot model inline asm: under `cfg(kani)` the proofs see the same
    // arithmetic mask (Linux's generic `array_index_mask_nospec`).
    #[cfg(any(kani, not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
    {
        let m = !(index | size.wrapping_sub(1).wrapping_sub(index)) as isize >> (usize::BITS - 1);
        #[cfg(kani)]
        return m as usize;
        #[cfg(not(kani))]
        core::hint::black_box(m as usize)
    }
}

/// `index` if `index < size`, else 0 — also under speculation. Call it after
/// the bounds check, on the index the load uses.
#[inline(always)]
pub fn array_index_nospec(index: usize, size: usize) -> usize {
    if ENABLED { index & mask(index, size) } else { index }
}

/// `slice.get(index)`, with the index masked on the in-bounds path.
#[inline(always)]
pub fn get<T>(slice: &[T], index: usize) -> Option<&T> {
    if index < slice.len() {
        let i = array_index_nospec(index, slice.len());
        // SAFETY: `i` is `index` (checked `< len` just above) or 0, and 0 is
        // in bounds because `len > index >= 0`.
        Some(unsafe { slice.get_unchecked(i) })
    } else {
        None
    }
}

/// `slice.get_mut(index)`, with the index masked on the in-bounds path.
#[inline(always)]
pub fn get_mut<T>(slice: &mut [T], index: usize) -> Option<&mut T> {
    if index < slice.len() {
        let i = array_index_nospec(index, slice.len());
        // SAFETY: as in `get`.
        Some(unsafe { slice.get_unchecked_mut(i) })
    } else {
        None
    }
}
