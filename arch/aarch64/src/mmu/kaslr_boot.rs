// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The boot half of aarch64 virtual KASLR (Kconfig `KASLR`): gather the seed,
//! choose the base, apply the relocations.
//!
//! **When it runs.** Once, on the boot CPU, from `boot.S`, after
//! `aarch64_early_mmu_init` (the identity map is live, so the image, the
//! relocation table and the device tree are all readable and writable at
//! their physical addresses) and before the jump to the upper half. The
//! image still holds link-time values in every pointer-bearing word: the
//! relocations are what this applies. So everything reachable from [`boot`]
//! must not read such a word. That constrains the code, not the data:
//!
//!  * addresses reach these functions as arguments from `boot.S`
//!    (`adrp`/`add`, so they are the physical addresses the PC runs at), never
//!    through a `static`'s address taken here, a vtable or a function pointer;
//!  * no `panic!`, no indexing, no formatting: the panic path loads a
//!    `Location` through a pointer the relocations have not fixed yet. The
//!    shared arithmetic in `azos_arch_api::kaslr` has the same rule.
//!
//! The code is position-independent (`adrp`/`add`/`bl`), the same property the
//! rest of the pre-jump boot already depends on: it runs at a low address
//! and was linked high.

use azos_arch_api::kaslr::{self as shared, Failure, SEED_DT, SEED_HW};

use super::kaslr::{run_plan, set_image_bias};
use super::KERNEL_VA_OFFSET;

/// `ID_AA64ISAR0_EL1.RNDR` (bits 63:60): FEAT_RNG.
#[inline(always)]
fn has_rng() -> bool {
    let isar0: u64;
    // SAFETY: an ID register read, legal at EL1 on every Armv8 core.
    unsafe { core::arch::asm!("mrs {0}, ID_AA64ISAR0_EL1", out(reg) isar0, options(nomem, nostack, preserves_flags)) };
    (isar0 >> 60) & 0xF != 0
}

/// One `RNDRRS` word, or `None` when Kconfig `A64_RNG` is `n`, the core has no
/// FEAT_RNG, or the source stays empty for the configured number of tries
/// (Kconfig `ENTROPY_CPU_RETRIES`).
#[inline(always)]
fn rndrrs() -> Option<u64> {
    if !azos_arch_api::isa::aarch64::RNG.gate(has_rng()) {
        return None;
    }
    let mut tries = 0u32;
    loop {
        let (v, ok): (u64, u64);
        // SAFETY: FEAT_RNG was just probed, so RNDRRS is readable at EL1. A
        // read with no data sets NZCV.Z (and returns 0); `cset ne` captures
        // it. Writes NZCV (no `preserves_flags`).
        unsafe {
            core::arch::asm!(
                "mrs {v}, S3_3_C2_C4_1",
                "cset {ok}, ne",
                v = out(reg) v, ok = out(reg) ok,
                options(nostack, nomem),
            );
        }
        if ok != 0 {
            return Some(v);
        }
        if tries >= azos_arch_api::entropy::RETRIES {
            return None;
        }
        tries += 1;
    }
}

/// The seed and which sources gave it. `dtb_bytes` is how much of the device
/// tree the identity map covers (0 = no device tree to read); a tree whose own
/// size (its header's `totalsize`) overlaps the image `[img, img_end)` is not
/// read (the walk writes there and the seed properties are erased in place).
///
/// # Safety
/// `dtb` must be readable and writable for `dtb_bytes` bytes through the
/// identity map when `dtb_bytes` is not 0.
unsafe fn seed(dtb: u64, dtb_bytes: usize, img: u64, img_end: u64) -> (Option<u64>, u64) {
    let hw = rndrrs();
    // The tree's own size, not the window it sits in (QEMU puts the Image
    // right behind its tree, inside that window).
    // SAFETY: the caller's contract.
    let dt_len = if dtb_bytes != 0 { unsafe { shared::fdt_size(dtb as *const u8, dtb_bytes) } } else { None };
    let dt = match dt_len {
        Some(n) if !shared::overlaps(dtb, n as u64, img, img_end.wrapping_sub(img)) => {
            // SAFETY: the caller's contract; the tree is `n` bytes, all inside the window.
            unsafe { shared::take_dt_seed(dtb as *mut u8, n) }
        }
        _ => None,
    };
    // A zero seed is the erased property of an earlier boot stage (or a
    // loader that left it blank): not a source.
    let dt = match dt { Some(0) => None, other => other };
    let sources = (hw.is_some() as u64) * SEED_HW | (dt.is_some() as u64) * SEED_DT;
    (shared::mix(hw, dt), sources)
}

/// Choose the image base, apply the relocations and record the result.
///
/// `img`/`img_end` are the physical addresses of `_start` and `_kernel_end`
/// (the image as the loader placed it), `rela`/`rela_end` those of the
/// relocation table inside it, `link_pa` the physical address the image was
/// linked to load at, `dtb` the device tree and `dtb_bytes` how much of it the
/// identity map covers.
///
/// The loader need not have put the image at `link_pa`: a Raspberry Pi 3's
/// RAM starts at 0 and its firmware loads the image at 0x80000, while the link
/// assumes QEMU `virt`'s 0x4008_0000. The image's home is then the linear
/// map's alias of where it actually is (`KERNEL_VA_OFFSET | img`), the slide
/// is chosen from there, and the relocation moves every pointer from the link
/// VA to the run VA in the same walk (`kaslr::run_plan`).
///
/// # Safety
/// Boot CPU, EL1, identity map live, the arguments as above, before any
/// relocation has been applied and before the jump to the upper half.
pub unsafe fn boot(
    dtb: u64,
    dtb_bytes: usize,
    img: u64,
    img_end: u64,
    rela: u64,
    rela_end: u64,
    link_pa: u64,
) -> Result<(), Failure> {
    // SAFETY: the caller's contract.
    let (entropy, sources) = unsafe { seed(dtb, dtb_bytes, img, img_end) };
    let bytes = img_end.wrapping_sub(img);
    // The link-time VA of the image's first byte: the link offset is the
    // linear map's, over the link physical address.
    let link_va = KERNEL_VA_OFFSET | link_pa;
    let (plan, delta) = run_plan(link_va, img, bytes, entropy);
    // Even with delta 0 the walk runs: the linker leaves a RELA target zero,
    // and the word must hold its link-time value. It runs before a `require`
    // refusal is reported too, so the message's own pointers are valid when it
    // is printed. Every target, and the table itself, is checked against
    // `[img, img_end)` first.
    // SAFETY: `rela..rela_end` lies inside the image (checked), which the
    // identity map maps writable and the caller owns; nothing else runs.
    let applied = unsafe {
        shared::relocate_image(img, img_end, rela, rela_end, link_va, delta, shared::R_AARCH64_RELATIVE)
    };
    if let Err(e) = applied {
        return Err(Failure::Relocation(e));
    }
    let plan = match plan {
        Ok(p) => p,
        Err(c) => return Err(Failure::Refused(c)),
    };
    // Recorded after the walk: `boot.S` reads the bias for the jump to the
    // upper half, and every secondary reads it when it starts.
    set_image_bias(plan.image_va.wrapping_sub(img), plan.bits, sources);
    Ok(())
}
