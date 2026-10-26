// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! riscv64 virtual KASLR (Kconfig `KASLR`): where the image may sit, and what
//! the rest of the kernel needs to know about where it did.
//!
//! **The layout.** The kernel runs identity-mapped (virtual = physical) in the
//! low half of Sv39, where RAM and the device windows are. The *upper half*
//! (VPN[2] 256..=511, `0xFFFF_FFC0_0000_0000` up, 256 GiB) holds nothing else,
//! so it is the image window: the kernel image, slid to a random 2 MiB-aligned
//! base inside it, is mapped there onto the frames the loader put it in. The
//! two halves never overlap, so a slid image is a second mapping of its own
//! frames (the identity alias is made read-only and not executable at boot,
//! as the x86_64 one is), and `phys_to_virt` stays the identity.
//!
//! | window       | step  | image in one root slot | bits (30 MiB image) |
//! |--------------|-------|------------------------|---------------------|
//! | 256 GiB      | 2 MiB | 1 GiB                  | about 16            |
//!
//! Sv39 only (the one paging mode this port has); the window is VPN[2]
//! slots 256..=511, every one of which is a kernel-only slot (above
//! `vmm::set_user_ceiling`), so every task root links the kernel's L1 table
//! for the slot word for word and the trap vector stays mapped in a user root.
//!
//! **Before the MMU.** A slid image runs from the first instruction of the
//! boot hart past the jump in `boot.S` on a boot root of its own
//! ([`AZOS_RV64_BOOT_SATP`], built by `kaslr_boot`: the low 256 GiB mapped
//! 1:1 with gigapages, plus the image window). Every other hart enters at the
//! physical `_secondary_start`, installs the same root and jumps to the slid
//! address; the kernel's own table (`vmm::enable_paging`) replaces it later.
//! SBI is handed physical addresses ([`phys_of`]).
//!
//! With the policy `n` (or a build with no window, KASLR_AVAILABLE false) the
//! whole layer is absent: [`ENABLED`] is false, the bias is 0 and every
//! function here folds to the identity the kernel had before.

use core::sync::atomic::{AtomicU64, Ordering};

use azos_arch_api::kaslr::Layout;

/// Does this build slide the image (Kconfig `KASLR` is not `n`, and available)?
pub const ENABLED: bool = azos_arch_api::kaslr::ENABLED;

/// The Sv39 image window: the whole upper half.
pub const LAYOUT: Layout = Layout {
    window_start: 0xFFFF_FFC0_0000_0000,
    window_bytes: 1 << 38,
    // One level-1 entry maps 2 MiB (a megapage)...
    align: 2 << 20,
    // ...and one root entry spans 1 GiB, one level-1 table for the image.
    no_cross: 1 << 30,
};
const _: () = assert!(LAYOUT.is_valid());
/// The window ends at the top of the address space.
const _: () = assert!(LAYOUT.window_start.wrapping_add(LAYOUT.window_bytes) == 0);

/// First VA of the image window.
pub const IMAGE_REGION_BASE: u64 = LAYOUT.window_start;
/// Low-half gigapages the boot root maps 1:1 (the whole low half of Sv39).
pub const BOOT_GIGAPAGES: usize = 256;

/// Run VA minus PA of the image: 0 while it runs at its link address (the
/// identity), `image_va - image_pa` once slid. Written by the boot hart
/// before the first MMU-on instruction, read by `boot.S` (`ld`, hence the
/// exported name) for the jump to the slid address, on every hart that starts.
#[unsafe(no_mangle)]
pub static AZOS_RV64_IMAGE_BIAS: AtomicU64 = AtomicU64::new(0);

/// The `satp` of the boot root (0 while the image is not slid). `boot.S`
/// installs it on every hart before it jumps to the slid address.
#[unsafe(no_mangle)]
pub static AZOS_RV64_BOOT_SATP: AtomicU64 = AtomicU64::new(0);

/// Bits of entropy the slide drew on; 0 when the image did not slide.
static SLIDE_BITS: AtomicU64 = AtomicU64::new(0);

/// Which seed sources fed the slide: [`azos_arch_api::kaslr::SEED_HW`] | [`azos_arch_api::kaslr::SEED_DT`].
static SEED_SOURCES: AtomicU64 = AtomicU64::new(0);

/// The hardware source the boot report names ([`azos_arch_api::kaslr::SEED_HW`]).
pub const HW_SOURCE: &str = "zkr";

/// Run VA minus PA of the image (0 when this build does not slide).
#[inline(always)]
pub fn image_bias() -> u64 {
    if ENABLED { AZOS_RV64_IMAGE_BIAS.load(Ordering::Relaxed) } else { 0 }
}

/// Did the boot move the image out of the identity map?
#[inline(always)]
pub fn image_slid() -> bool {
    ENABLED && image_bias() != 0
}

/// Is `va` in the image window? False for every address when this build does
/// not slide: the identity is then the only map.
#[inline(always)]
pub fn is_image_va(va: u64) -> bool {
    ENABLED && va >= IMAGE_REGION_BASE
}

/// The physical address of an image VA.
#[inline(always)]
pub fn image_phys(va: u64) -> u64 {
    va.wrapping_sub(image_bias())
}

/// The physical address behind a kernel VA for the firmware: an image address
/// through the bias, anything else as it is (the identity). SBI is handed
/// resume and start addresses of code in the image through this.
#[inline(always)]
pub fn phys_of(va: u64) -> u64 {
    if is_image_va(va) { image_phys(va) } else { va }
}

/// Record where the boot put the image (run VA minus PA), its boot root and
/// how it chose. Boot hart only, before any conversion of an image address.
pub fn set_image_bias(bias: u64, satp: u64, bits: u32, sources: u64) {
    SLIDE_BITS.store(bits as u64, Ordering::Relaxed);
    SEED_SOURCES.store(sources, Ordering::Relaxed);
    AZOS_RV64_BOOT_SATP.store(satp, Ordering::Relaxed);
    AZOS_RV64_IMAGE_BIAS.store(bias, Ordering::Release);
}

/// Entropy bits of the slide (0 = not slid).
pub fn slide_bits() -> u32 {
    SLIDE_BITS.load(Ordering::Relaxed) as u32
}

/// The seed sources of the slide ([`azos_arch_api::kaslr::SEED_HW`] | [`azos_arch_api::kaslr::SEED_DT`]).
pub fn seed_sources() -> u64 {
    SEED_SOURCES.load(Ordering::Relaxed)
}

// ── the boot root, as numbers (pure, host-tested) ────────────────────────

/// PTE bits of a kernel leaf the boot root uses: V R W X A D.
pub const BOOT_LEAF: u64 = 0xCF;
/// The same without X: the low half's gigapages that hold no code (RAM beyond
/// the image, devices). A hart executes on the 1:1 map only for the few
/// instructions between writing `satp` and jumping to the slid base, and only
/// inside the image's own gigapage(s).
pub const BOOT_DATA_LEAF: u64 = 0xC7;
/// PTE bit V (a non-leaf PTE is V alone).
pub const PTE_V: u64 = 1;

/// The boot root's gigapage `i`: the identity leaf over `[i GiB, i + 1 GiB)`,
/// executable when `exec` (the gigapage holds the image).
pub const fn boot_gigapage(i: usize, exec: bool) -> u64 {
    // PPN = PA >> 12, stored from bit 10: PA = i << 30 -> i << 28.
    ((i as u64) << 28) | if exec { BOOT_LEAF } else { BOOT_DATA_LEAF }
}

/// A non-leaf PTE naming the page table at physical address `pa`.
pub const fn table_pte(pa: u64) -> u64 {
    ((pa >> 12) << 10) | PTE_V
}

/// A megapage leaf onto physical address `pa` (2 MiB-aligned).
pub const fn mega_pte(pa: u64) -> u64 {
    ((pa >> 12) << 10) | BOOT_LEAF
}

/// `satp` for an Sv39 root at physical address `root_pa`, ASID 0.
pub const fn boot_satp(root_pa: u64) -> u64 {
    (8u64 << 60) | (root_pa >> 12)
}

/// Sv39 VPN[2] / VPN[1] of a VA.
pub const fn vpn2(va: u64) -> usize {
    ((va >> 30) & 0x1FF) as usize
}
pub const fn vpn1(va: u64) -> usize {
    ((va >> 21) & 0x1FF) as usize
}

/// Fill the boot root and the image's level-1 table (both zero to begin with)
/// for an image mapped `blocks` megapages from `va_block` onto `pa_block`:
/// the low half 1:1 with gigapages (executable only where the image's frames
/// are), the image's root entry naming the level-1 table at physical address
/// `l1_pa`. Panic-free (the boot runs it before the relocations are applied);
/// an entry that would fall outside its table is not written. Returns the
/// blocks written.
pub fn fill_boot_root(
    root: &mut [u64; 512],
    l1: &mut [u64; 512],
    l1_pa: u64,
    va_block: u64,
    pa_block: u64,
    blocks: u64,
) -> u64 {
    let code_first = (pa_block >> 30) as usize;
    let code_last = ((pa_block + blocks * LAYOUT.align).wrapping_sub(1) >> 30) as usize;
    let mut i = 0usize;
    while i < BOOT_GIGAPAGES {
        root[i] = boot_gigapage(i, i >= code_first && i <= code_last);
        i += 1;
    }
    let first = vpn1(va_block);
    let mut k = 0u64;
    while k < blocks {
        if let Some(e) = l1.get_mut(first + k as usize) {
            *e = mega_pte(pa_block + k * LAYOUT.align);
        } else {
            break;
        }
        k += 1;
    }
    root[vpn2(va_block)] = table_pte(l1_pa);
    k
}
