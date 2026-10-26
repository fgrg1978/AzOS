// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 virtual KASLR (Kconfig `KASLR`): where the image may sit, and what
//! the rest of the kernel needs to know about where it did.
//!
//! **The layout.** `-mcmodel=kernel` holds the image to the top 2 GiB of the
//! address space (an absolute reference is a sign-extended 32-bit operand),
//! and the AP start tables map one GiB of image (`smp::build_image_map`,
//! [`super::IMAGE_WINDOW`]), so the *image window* is the first GiB of the
//! top 2 GiB: `0xFFFF_FFFF_8000_0000 + [0, 1 GiB)`, in 2 MiB steps (one page
//! directory entry each). A 30 MiB image has about 480 positions, 8 whole
//! bits; Linux's x86_64 kernel has the same window and step. RAM lives in the
//! direct map (`DIRECT_MAP_BASE`), a different root slot, so the window holds
//! the image alone and `phys_to_virt` stays one add.
//!
//! **What slides.** Only the virtual base. The image's physical place is the
//! loader's (PVH puts it at 1 MiB), and everything that converts an image
//! address to a physical one already goes through [`super::image_phys`], whose
//! recorded slide (`image_slide`) is `pa - (va - KERNEL_VA_OFFSET)`: a virtual
//! slide of `s` is a recorded slide of `-s`, the same single number a Limine
//! physical placement uses (that image is not slid virtually: its choice is
//! hidden, KASLR_AVAILABLE).
//!
//! **Before paging is the kernel's.** The 32-bit boot stage maps the image at
//! its link address as it always did and enters 64-bit mode on the 1:1 half;
//! `x86_64_early_kaslr` (`kaslr_boot`) then runs at the physical address,
//! picks the base, applies the image's `R_X86_64_RELATIVE` relocations, hangs a
//! page directory for the slid image from the top-2-GiB PDPT and the boot
//! stage jumps to the slid address. The kernel's own tables
//! (`vmm::map_kernel_image`) map the image there again before the boot tables
//! are dropped.
//!
//! With the policy `n` (or a build with no window) the layer is absent:
//! [`ENABLED`] is false and every function here folds to the arithmetic the
//! kernel had before.

use core::sync::atomic::{AtomicU64, Ordering};

use azos_arch_api::kaslr::Layout;

use super::{IMAGE_WINDOW, KERNEL_VA_OFFSET};

/// Does this build slide the image (Kconfig `KASLR` is not `n`, and available)?
pub const ENABLED: bool = azos_arch_api::kaslr::ENABLED;

/// The image window: the first GiB of the top 2 GiB, 2 MiB steps, inside one
/// page directory (one PDPT entry).
pub const LAYOUT: Layout = Layout {
    window_start: KERNEL_VA_OFFSET,
    window_bytes: IMAGE_WINDOW,
    align: 2 << 20,
    no_cross: IMAGE_WINDOW,
};
const _: () = assert!(LAYOUT.is_valid());

/// First VA of the image window.
pub const IMAGE_REGION_BASE: u64 = LAYOUT.window_start;

/// Bits of entropy the slide drew on; 0 when the image did not slide.
static SLIDE_BITS: AtomicU64 = AtomicU64::new(0);

/// Which seed sources fed the slide: [`azos_arch_api::kaslr::SEED_HW`] | [`azos_arch_api::kaslr::SEED_DT`].
static SEED_SOURCES: AtomicU64 = AtomicU64::new(0);

/// The hardware source the boot report names ([`azos_arch_api::kaslr::SEED_HW`]).
pub const HW_SOURCE: &str = "rdseed/rdrand";

/// Did the boot move the image from its link address?
#[inline(always)]
pub fn image_slid() -> bool {
    ENABLED && slide_bits() != 0
}

/// Record how the boot chose. Boot CPU only; the recorded slide itself is
/// [`super::set_image_slide`]'s.
#[inline(always)]
pub fn set_boot_result(bits: u32, sources: u64) {
    SLIDE_BITS.store(bits as u64, Ordering::Relaxed);
    SEED_SOURCES.store(sources, Ordering::Relaxed);
}

/// Entropy bits of the slide (0 = not slid).
pub fn slide_bits() -> u32 {
    SLIDE_BITS.load(Ordering::Relaxed) as u32
}

/// The seed sources of the slide ([`azos_arch_api::kaslr::SEED_HW`] | [`azos_arch_api::kaslr::SEED_DT`]).
pub fn seed_sources() -> u64 {
    SEED_SOURCES.load(Ordering::Relaxed)
}

/// The recorded slide (`image_phys` = `va - KERNEL_VA_OFFSET + slide`) of an
/// image moved virtually by `virtual_slide` bytes and not physically.
#[inline(always)]
pub const fn recorded_slide(virtual_slide: u64) -> u64 {
    0u64.wrapping_sub(virtual_slide)
}

/// The two PD-level facts of a slid image: PD index of its first 2 MiB block
/// (counted from [`IMAGE_REGION_BASE`]) and the physical address of that
/// block, for the image whose first byte is at `image_va` / `image_pa`.
#[inline(always)]
pub const fn first_block(image_va: u64, image_pa: u64) -> (usize, u64) {
    let mask = LAYOUT.align - 1;
    (((image_va & !mask) - IMAGE_REGION_BASE) as usize >> 21, image_pa & !mask)
}

/// Fill the slid image's page directory (zero to begin with): `blocks` 2 MiB
/// leaves from entry `first`, onto the frames from `pa_block`, present and
/// writable like the rest of the boot map (no NX, no user bit). Panic-free (the
/// boot runs it before the relocations are applied); an entry that would fall
/// outside the table is not written. Returns the blocks written.
#[inline(always)]
pub fn fill_image_pd(pd: &mut [u64; 512], first: usize, pa_block: u64, blocks: u64) -> u64 {
    const P: u64 = 1;
    const RW: u64 = 1 << 1;
    const PS: u64 = 1 << 7;
    let mut k = 0u64;
    while k < blocks {
        if let Some(e) = pd.get_mut(first + k as usize) {
            *e = (pa_block + k * LAYOUT.align) | P | RW | PS;
        } else {
            break;
        }
        k += 1;
    }
    k
}
