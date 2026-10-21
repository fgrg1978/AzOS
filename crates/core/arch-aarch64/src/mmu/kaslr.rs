// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 virtual KASLR (Kconfig `KASLR`): where the image may sit, and what
//! the rest of the kernel needs to know about where it did.
//!
//! **The layout.** The upper half of the kernel's address range (TTBR1,
//! `KERNEL_VA_OFFSET` up) is cut in two. The lower half is the linear map:
//! RAM at `pa | KERNEL_VA_OFFSET`, as always. The upper half is the *image
//! window*: the kernel image, slid to a random block-aligned base inside it,
//! is mapped there onto the frames the loader put it in. The two halves never
//! overlap, so a slid image is a second mapping of its own frames (the linear
//! map keeps an alias, made read-only and not executable at boot), and
//! `phys_to_virt` stays one OR.
//!
//! | granule | VA bits | linear map (RAM < )  | image window       | slide step |
//! |---------|---------|----------------------|--------------------|------------|
//! | 4 KiB   | 39      | 256 GiB              | 256 GiB            | 2 MiB      |
//! | 16 KiB  | 39      | 256 GiB              | 256 GiB            | 32 MiB     |
//! | 64 KiB  | 48      | 128 TiB              | 128 TiB            | 512 MiB    |
//!
//! The step is the size of one level-2 block, so the early boot maps the
//! image with blocks and no level-3 table; the image sits inside one root
//! entry's span (1 GiB, 64 GiB, 4 TiB) so one level-2 table maps all of it.
//!
//! **What the rest of the kernel asks.** Which VA is the image
//! ([`is_image_va`]), and the physical address of an image VA
//! ([`image_phys`], [`kva_to_pa`]). An image address is no longer
//! `pa | KERNEL_VA_OFFSET`, so every conversion of a symbol's address to a
//! physical one goes through `azos_mm::addr::virt_to_phys` (which calls
//! these); the early boot, which runs before the first conversion, records
//! the base ([`set_image_bias`]).
//!
//! With the policy `n` the whole layer is absent: [`ENABLED`] is false, the
//! bias is the constant `KERNEL_VA_OFFSET`, and every function here folds to
//! the single-offset arithmetic the kernel had before.

use core::sync::atomic::{AtomicU64, Ordering};

use azos_arch_api::kaslr::Layout;

use super::{Granule, GRANULE, KERNEL_VA_OFFSET};

/// Does this build slide the image (Kconfig `KASLR` is not `n`, on aarch64)?
pub const ENABLED: bool = azos_arch_api::kaslr::ENABLED;

/// The image window's layout for a granule: the upper half of its upper-half
/// range, in blocks of one level-2 block, one level-1 root entry per table.
pub const fn layout_for(g: Granule) -> Layout {
    let bytes = 1u64 << (g.va_bits - 1);
    Layout {
        window_start: g.kernel_va_offset() + bytes,
        window_bytes: bytes,
        align: g.level_size(1) as u64,
        no_cross: g.level_size(2) as u64,
    }
}

/// The layout this build boots with.
pub const LAYOUT: Layout = layout_for(GRANULE);
const _: () = assert!(LAYOUT.is_valid());

/// First VA of the image window; the linear map ends below it.
pub const IMAGE_REGION_BASE: u64 = LAYOUT.window_start;
/// Bytes of physical address the linear map can reach (RAM above this has no
/// linear alias and is left out of the allocator by the platform code).
pub const LINEAR_MAP_BYTES: u64 = LAYOUT.window_bytes;
const _: () = assert!(IMAGE_REGION_BASE == KERNEL_VA_OFFSET + LINEAR_MAP_BYTES);

/// Run VA minus PA of the image: `KERNEL_VA_OFFSET` when it runs inside the
/// linear map (the link-time layout), `image_va - image_pa` once slid.
/// Written by the boot CPU before the first MMU-on instruction past the
/// relocations, read by `boot.S` (`ldr`, hence the exported name) for the
/// jump to the upper half and by every secondary for the same jump.
#[unsafe(no_mangle)]
pub static AZOS_IMAGE_BIAS: AtomicU64 = AtomicU64::new(KERNEL_VA_OFFSET);

/// Bits of entropy the slide drew on (`slide_bits` of the slot count); 0 when
/// the image did not slide. Read by the boot report.
static SLIDE_BITS: AtomicU64 = AtomicU64::new(0);

/// Which seed sources fed the slide: [`azos_arch_api::kaslr::SEED_HW`] | [`azos_arch_api::kaslr::SEED_DT`].
static SEED_SOURCES: AtomicU64 = AtomicU64::new(0);

/// The hardware source the boot report names ([`azos_arch_api::kaslr::SEED_HW`]).
pub const HW_SOURCE: &str = "rndrrs";

/// Run VA minus PA of the image (the constant `KERNEL_VA_OFFSET` when this
/// build does not slide).
#[inline(always)]
pub fn image_bias() -> u64 {
    if ENABLED { AZOS_IMAGE_BIAS.load(Ordering::Relaxed) } else { KERNEL_VA_OFFSET }
}

/// Did the boot move the image out of the linear map?
#[inline(always)]
pub fn image_slid() -> bool {
    ENABLED && image_bias() != KERNEL_VA_OFFSET
}

/// Is `va` in the image window? False for every address when this build does
/// not slide: the linear map is then the only map.
#[inline(always)]
pub fn is_image_va(va: u64) -> bool {
    ENABLED && va >= IMAGE_REGION_BASE
}

/// The physical address of an image VA.
#[inline(always)]
pub fn image_phys(va: u64) -> u64 {
    va.wrapping_sub(image_bias())
}

/// [`kva_to_pa`] for a granule and an image bias (pure).
#[inline(always)]
pub const fn kva_to_pa_for(g: Granule, va: u64, bias: u64) -> u64 {
    if va >= layout_for(g).window_start { va.wrapping_sub(bias) } else { va & !g.kernel_va_offset() }
}

/// The physical address behind a kernel VA: an image address through the
/// image bias, anything else (a linear-map address, or an address already
/// physical) by clearing the offset bits. This is the one conversion for a
/// kernel `static` handed to hardware.
#[inline(always)]
pub fn kva_to_pa(va: u64) -> u64 {
    if ENABLED { kva_to_pa_for(GRANULE, va, image_bias()) } else { va & !KERNEL_VA_OFFSET }
}

/// Record where the boot put the image (run VA minus PA) and how it chose.
/// Boot CPU only, before any conversion of an image address.
pub fn set_image_bias(bias: u64, bits: u32, sources: u64) {
    AZOS_IMAGE_BIAS.store(bias, Ordering::Release);
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
