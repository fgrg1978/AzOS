// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kernel virtual address-space layout randomization (Kconfig `KASLR`), the
//! parts every ISA shares and a host can test: the policy, the slide
//! choice, the relocation walk and the device-tree seed.
//!
//! **What is randomized.** The kernel image's virtual base, on all three ISAs.
//! The image is linked position-independent (a `-pie` link, kernel/build.rs;
//! the code is PC-relative, `tools/kconfig_to_cargo.py` `kaslr_rustflags`), the boot
//! picks a random, block-aligned virtual base inside the ISA's image window,
//! maps the image there and applies the image's relative relocations
//! (`R_*_RELATIVE`) with the difference between that base and the link
//! address. Nothing else moves: the linear map of RAM keeps its fixed
//! offset (aarch64, x86_64's direct map) or its identity (riscv64), which is
//! why the window must not overlap it (the ISA's layout says where it is).
//!
//! | ISA     | image window                                  | step  | where the seed comes from        |
//! |---------|-----------------------------------------------|-------|----------------------------------|
//! | aarch64 | upper half of the TTBR1 range (256 GiB, 4 KiB)| 2 MiB | RNDRRS, `/chosen/kaslr-seed`     |
//! | riscv64 | the Sv39 upper half (256 GiB)                 | 2 MiB | Zkr `seed` CSR, `/chosen` seeds  |
//! | x86_64  | the first GiB of the top 2 GiB (`-mcmodel=kernel`) | 2 MiB | RDSEED, RDRAND             |
//!
//! **Why these functions are panic-free and pointer-based.** The boot runs
//! them before the relocations are applied, on a stack with no frame to
//! unwind to: a panic would reach the panic handler through a relocated
//! pointer that does not hold a valid address yet. They index nothing,
//! allocate nothing, return a value for every input, and touch no `static`.
//!
//! The ISA crates own the layout numbers ([`Layout`]) and the entropy
//! sources; this module owns the arithmetic, so the same tests cover every
//! ISA's numbers.

use crate::isa::ExtPolicy;

/// Kconfig `KASLR`: `n` never randomizes, `probe` randomizes when the boot
/// finds entropy, `require` refuses to boot without it.
pub const POLICY: ExtPolicy = ExtPolicy::from_kconfig(azos_limits::KASLR_NEVER, azos_limits::KASLR_REQUIRE);

/// Is this build position-independent and does its boot try to slide it?
/// `KASLR_AVAILABLE` (config/Kconfig.security) is false where the choice is
/// hidden (a small riscv64 board, the x86_64 Limine image), which a hidden
/// choice would otherwise read as `probe`; then no relocation code is built.
pub const ENABLED: bool = azos_limits::KASLR_AVAILABLE && POLICY.allowed();

/// Seed bookkeeping the boot reports: the hardware source
/// (RNDRRS, the `seed` CSR, RDSEED/RDRAND) fed the slide.
pub const SEED_HW: u64 = 1;
/// The device tree's `/chosen/kaslr-seed` or `/chosen/rng-seed` fed the slide.
pub const SEED_DT: u64 = 2;

// ── the slide ──────────────────────────────────────────────────────────────
//
// **Every function the boot calls before its relocations are applied is
// `#[inline(always)]`.** A call from another crate is, in a `pie` link (x86_64
// with the retpoline thunks), `movq f@GOTPCREL(%rip), %r11; call
// __x86_indirect_thunk_r11`: a load from a GOT slot that holds zero until the
// walk this module implements has run. The build asks the linker to relax such
// loads (`-Z relax-elf-relocations`, tools/kconfig_to_cargo.py); inlined into
// the arch crate's boot function, the arithmetic is code in one place and
// calls nothing, whatever the linker does.

/// Where an ISA lets the kernel image sit, in bytes of virtual address
/// space counted from the window's start (so no value here has to represent
/// 2^64, the top of an upper-half window).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// First virtual address of the image window.
    pub window_start: u64,
    /// Size of the window in bytes.
    pub window_bytes: u64,
    /// Granule of the slide: the image's virtual and physical addresses
    /// agree modulo this, so the boot maps it with blocks of this size
    /// (2 MiB at a 4 KiB granule on aarch64).
    pub align: u64,
    /// The image must not straddle a multiple of this (the span one
    /// page-table root entry covers), so one table maps all of it. A power
    /// of two that is a multiple of `align`; `window_start` and
    /// `window_bytes` are multiples of it.
    pub no_cross: u64,
}

impl Layout {
    /// Is the layout internally consistent (the checks the tests and the
    /// boot's `const` assertions rely on)?
    pub const fn is_valid(&self) -> bool {
        self.align.is_power_of_two()
            && self.no_cross.is_power_of_two()
            && self.no_cross >= self.align
            && self.window_start % self.no_cross == 0
            && self.window_bytes != 0
            && self.window_bytes % self.no_cross == 0
    }
}

/// The image placed by [`pick_slide`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slide {
    /// Virtual address of the image's first byte.
    pub image_va: u64,
    /// Virtual address of the first mapped block (`image_va` rounded down to
    /// the layout's `align`).
    pub block_va: u64,
    /// Blocks the image occupies from `block_va`.
    pub blocks: u64,
}

/// Why no slide was chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlideError {
    /// The layout is not [`Layout::is_valid`].
    BadLayout,
    /// The image (plus its offset inside its first block) does not fit in
    /// one `no_cross` span.
    ImageTooLarge,
}

/// Choose the image's virtual base.
///
/// `phase` is the image's physical start modulo `layout.align` (virtual and
/// physical addresses must agree modulo the block size for a block map), and
/// `bytes` its size from first byte to the end of its last page. `entropy`
/// is the seed; every valid slot is equally likely up to a modulo bias of
/// `slots / 2^64`, below 2^-20 for any window a 64-bit address space has.
///
/// The result is deterministic in its inputs and always satisfies: inside
/// the window; `image_va % align == phase`; no `no_cross` boundary inside
/// `[image_va, image_va + bytes)`.
#[inline(always)]
pub const fn pick_slide(layout: &Layout, phase: u64, bytes: u64, entropy: u64) -> Result<Slide, SlideError> {
    let g = match geometry(layout, phase, bytes) {
        Ok(g) => g,
        Err(e) => return Err(e),
    };
    let slot = entropy % g.slots;
    let region = slot / g.starts;
    let start = slot % g.starts;
    let block_va = layout.window_start + region * layout.no_cross + start * layout.align;
    Ok(Slide { image_va: block_va + phase, block_va, blocks: g.blocks })
}

/// The number of distinct slides [`pick_slide`] can return (0 when it would
/// return an error); the entropy it draws on is [`slide_bits`] of this.
#[inline(always)]
pub const fn slide_slots(layout: &Layout, phase: u64, bytes: u64) -> u64 {
    match geometry(layout, phase, bytes) {
        Ok(g) => g.slots,
        Err(_) => 0,
    }
}

/// The counts a slide is chosen from.
struct Geometry {
    /// Blocks the image touches.
    blocks: u64,
    /// Start blocks inside one `no_cross` region that keep the image whole.
    starts: u64,
    /// Slides in the window: regions times starts. Never 0.
    slots: u64,
}

#[inline(always)]
const fn geometry(layout: &Layout, phase: u64, bytes: u64) -> Result<Geometry, SlideError> {
    if !layout.is_valid() || phase >= layout.align || bytes == 0 {
        return Err(SlideError::BadLayout);
    }
    let span = match phase.checked_add(bytes) {
        Some(s) => s,
        None => return Err(SlideError::ImageTooLarge),
    };
    let blocks = (span - 1) / layout.align + 1;
    let per_region = layout.no_cross / layout.align;
    if blocks > per_region {
        return Err(SlideError::ImageTooLarge);
    }
    let starts = per_region - blocks + 1;
    let regions = layout.window_bytes / layout.no_cross;
    Ok(Geometry { blocks, starts, slots: regions * starts })
}

/// Whole bits of `slots` (floor of log2; 0 for 0 or 1 slot).
#[inline(always)]
pub const fn slide_bits(slots: u64) -> u32 {
    if slots < 2 { 0 } else { 63 - slots.leading_zeros() }
}

/// What the boot does, once it knows the policy and whether it got entropy
/// and a slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Slide the image to this base.
    Slide(Slide),
    /// Keep the link address: the policy is `probe` and nothing could be
    /// chosen (no entropy source, or the image does not fit).
    Unslid(Cause),
    /// Refuse to boot: the policy is `require` and nothing could be chosen.
    Refuse(Cause),
}

/// Why there is no slide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// No entropy source answered.
    NoEntropy,
    /// The layout or the image size leaves no slot.
    NoSlot,
}

impl Cause {
    /// The words the boot prints.
    pub const fn text(self) -> &'static str {
        match self {
            Cause::NoEntropy => "no entropy source (the CPU's random-number source, or a device-tree seed)",
            Cause::NoSlot => "no slot for the image in the window",
        }
    }
}

/// Resolve the policy. `entropy` is `None` when no source answered.
#[inline(always)]
pub const fn decide(policy: ExtPolicy, layout: &Layout, phase: u64, bytes: u64, entropy: Option<u64>) -> Outcome {
    if !policy.allowed() {
        // Never reached by a build whose policy is `n` (it compiles no
        // relocation code); kept total so the tests cover every policy.
        return Outcome::Unslid(Cause::NoSlot);
    }
    let cause = match entropy {
        None => Cause::NoEntropy,
        Some(e) => match pick_slide(layout, phase, bytes, e) {
            Ok(s) => return Outcome::Slide(s),
            Err(_) => Cause::NoSlot,
        },
    };
    match policy {
        ExtPolicy::Require => Outcome::Refuse(cause),
        _ => Outcome::Unslid(cause),
    }
}

/// Fold two entropy words (either may be absent) into one seed. XOR of
/// independent sources is at least as unpredictable as the best of them; a
/// source an attacker can read (a device-tree seed that stayed in memory)
/// does not weaken a hardware one it is mixed with.
#[inline(always)]
pub const fn mix(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (None, None) => None,
        (Some(x), None) | (None, Some(x)) => Some(x),
        (Some(x), Some(y)) => Some(x ^ y),
    }
}

/// The numbers a boot acts on once the policy is resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Added to every relocation addend: run VA minus link VA, wrapping. 0
    /// when the image stays where it was linked.
    pub delta: u64,
    /// The run VA of the image's first byte.
    pub image_va: u64,
    /// Whole bits of entropy the slide drew on; 0 when it did not slide.
    pub bits: u32,
}

/// Resolve the build's policy ([`POLICY`]) for an image of `bytes` bytes whose
/// first byte is linked at `link_va` and loaded at `img_pa`, with `entropy`
/// (`None` = no source answered). `Err` is the cause of a `require` refusal.
#[inline(always)]
pub const fn plan(layout: &Layout, link_va: u64, img_pa: u64, bytes: u64, entropy: Option<u64>) -> Result<Plan, Cause> {
    let phase = img_pa & layout.align.wrapping_sub(1);
    match decide(POLICY, layout, phase, bytes, entropy) {
        Outcome::Slide(s) => Ok(Plan {
            delta: s.image_va.wrapping_sub(link_va),
            image_va: s.image_va,
            bits: slide_bits(slide_slots(layout, phase, bytes)),
        }),
        Outcome::Unslid(_) => Ok(Plan { delta: 0, image_va: link_va, bits: 0 }),
        Outcome::Refuse(c) => Err(c),
    }
}

/// The blocks an image mapping needs, from the chosen base: the first block's
/// VA and PA (both rounded down to the block) and the block count, for an
/// image of `bytes` whose first byte is at `image_va` / `image_pa`.
///
/// `image_va` and `image_pa` agree modulo the block, by construction of the
/// slide ([`pick_slide`]'s `phase`).
#[inline(always)]
pub const fn image_blocks(layout: &Layout, image_va: u64, image_pa: u64, bytes: u64) -> (u64, u64, u64) {
    let mask = layout.align - 1;
    let va_block = image_va & !mask;
    let pa_block = image_pa & !mask;
    let blocks = (image_pa - pa_block + bytes + mask) / layout.align;
    (va_block, pa_block, blocks)
}

/// Do `[a, a + alen)` and `[b, b + blen)` share a byte? (Empty ranges never.)
#[inline(always)]
pub const fn overlaps(a: u64, alen: u64, b: u64, blen: u64) -> bool {
    alen != 0 && blen != 0 && a < b.saturating_add(blen) && b < a.saturating_add(alen)
}

/// Why the boot cannot continue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Policy `require` and no slide could be chosen.
    Refused(Cause),
    /// The relocation table holds something the walk does not apply.
    Relocation(RelocError),
}

impl Failure {
    /// The line the boot prints on its early console before it stops: no
    /// console exists yet, so these are fixed byte strings.
    pub const fn text(&self) -> &'static [u8] {
        match self {
            Failure::Refused(Cause::NoEntropy) => {
                b"\r\n[KASLR] FATAL: Kconfig KASLR_REQUIRE, but no entropy source answered (the CPU's random-number source, or a device-tree seed); refusing to boot. Choose probe or n in make config, or boot a CPU or loader that supplies a seed.\r\n"
            }
            Failure::Refused(Cause::NoSlot) => {
                b"\r\n[KASLR] FATAL: Kconfig KASLR_REQUIRE, but the image fits no slot in the image window; refusing to boot.\r\n"
            }
            Failure::Relocation(RelocError::EmptyTable) => {
                b"\r\n[KASLR] FATAL: the image has no relocation table: it was not linked position-independent (the `-pie` link, kernel/build.rs), so its pointers cannot follow a slide; refusing to boot. Rebuild the kernel, or choose n in make config.\r\n"
            }
            Failure::Relocation(_) => {
                b"\r\n[KASLR] FATAL: the relocation table has an entry that is not a relative relocation or lies outside the image, or the table itself is outside it; refusing to boot. The link was not the position-independent one this boot expects.\r\n"
            }
        }
    }
}

// ── relocations ────────────────────────────────────────────────────────────

/// `Elf64_Rela`: 24 bytes.
pub const RELA_BYTES: usize = 24;

/// `R_AARCH64_RELATIVE`.
pub const R_AARCH64_RELATIVE: u32 = 1027;
/// `R_RISCV_RELATIVE`.
pub const R_RISCV_RELATIVE: u32 = 3;
/// `R_X86_64_RELATIVE`.
pub const R_X86_64_RELATIVE: u32 = 8;

/// Why [`apply_relative`] stopped. Every variant is a build defect or a
/// corrupt image: the boot reports it and halts, since a half-relocated
/// kernel cannot run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelocError {
    /// The table's size is not a whole number of entries.
    TableSize,
    /// Entry `index` is not the relative type the ISA's linker emits:
    /// a symbol-bound relocation means the link was not position-independent
    /// in the way this code assumes.
    UnsupportedType { index: usize, ty: u32 },
    /// Entry `index` writes outside `[link_start, link_start + len)`.
    OutsideImage { index: usize },
    /// The table itself is not inside the image it relocates (a boot stage
    /// handed over bounds that do not belong to this image).
    TableOutsideImage,
    /// The table is empty: the image was not linked `-pie`. A Rust kernel
    /// always holds pointers in data (vtables, the registries), so an image
    /// with nothing to relocate is a link that lost its position-independent
    /// flags, not one that needs none; slid, its data would keep pointing at
    /// the link address and the boot would die at the first indirect call
    /// once that address's alias stops being executable.
    EmptyTable,
}

/// Apply every `R_*_RELATIVE` entry of the table `[rela, rela + rela_bytes)`
/// to the image bytes at `dest`.
///
/// An entry says: the 64-bit word at link address `r_offset` holds
/// `r_addend` + (the image's link-to-run distance). `link_start` is the
/// link address of the image's first byte and `len` its size in bytes, so
/// the word lives at `dest + (r_offset - link_start)`; `delta` is the
/// distance (run address minus link address, wrapping) and `ty` the ISA's
/// relative type. The word becomes `r_addend + delta`, wrapping.
///
/// Returns the number of entries applied. Stops at the first entry it
/// cannot apply, leaving earlier ones applied.
///
/// # Safety
/// `rela` must be readable for `rela_bytes`, `dest` writable for `len`
/// bytes, and nothing else may access either meanwhile. Both may be
/// unaligned.
#[inline(always)]
pub unsafe fn apply_relative(
    rela: *const u8,
    rela_bytes: usize,
    dest: *mut u8,
    len: u64,
    link_start: u64,
    delta: u64,
    ty: u32,
) -> Result<usize, RelocError> {
    if rela_bytes % RELA_BYTES != 0 {
        return Err(RelocError::TableSize);
    }
    let n = rela_bytes / RELA_BYTES;
    let mut i = 0usize;
    while i < n {
        // SAFETY: i < n, so the entry lies inside the caller's table.
        let (off, info, addend) = unsafe {
            let e = rela.add(i * RELA_BYTES);
            (
                core::ptr::read_unaligned(e as *const u64),
                core::ptr::read_unaligned(e.add(8) as *const u64),
                core::ptr::read_unaligned(e.add(16) as *const u64),
            )
        };
        let t = info as u32;
        if t != ty {
            return Err(RelocError::UnsupportedType { index: i, ty: t });
        }
        let rel = off.wrapping_sub(link_start);
        if off < link_start || rel > len || len - rel < 8 {
            return Err(RelocError::OutsideImage { index: i });
        }
        // SAFETY: rel + 8 <= len, so the word is inside the image.
        unsafe { core::ptr::write_unaligned(dest.add(rel as usize) as *mut u64, addend.wrapping_add(delta)) };
        i += 1;
    }
    Ok(n)
}

/// [`apply_relative`] for the image `[img, img_end)` (physical, where the boot
/// runs and the image is writable) with its table `[rela, rela_end)`, which
/// must lie inside the image: the bounds come from linker symbols the boot
/// stage took with PC-relative addressing, and a stage that passed anything
/// else would have the walk read an arbitrary table and write wherever its
/// entries point. Every entry's target is then checked against the image. An
/// empty table is refused ([`RelocError::EmptyTable`]): the boot calls this
/// only for a KASLR build, whose `-pie` link always has entries.
///
/// # Safety
/// As [`apply_relative`]: the image is writable at `img` for its length,
/// and nothing else accesses it meanwhile.
#[inline(always)]
pub unsafe fn relocate_image(
    img: u64,
    img_end: u64,
    rela: u64,
    rela_end: u64,
    link_va: u64,
    delta: u64,
    ty: u32,
) -> Result<usize, RelocError> {
    if img_end < img || rela < img || rela_end < rela || rela_end > img_end {
        return Err(RelocError::TableOutsideImage);
    }
    if rela_end == rela {
        return Err(RelocError::EmptyTable);
    }
    // SAFETY: the table is inside the image (above), which the caller owns.
    unsafe { apply_relative(rela as *const u8, (rela_end - rela) as usize, img as *mut u8, img_end - img, link_va, delta, ty) }
}

// ── the device-tree seed ───────────────────────────────────────────────────

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

/// Read a big-endian u32 at `blob + off` if `off + 4 <= total`.
///
/// # Safety
/// `blob` must be readable for `total` bytes.
#[inline(always)]
unsafe fn be32(blob: *const u8, total: usize, off: usize) -> Option<u32> {
    if off > total || total - off < 4 {
        return None;
    }
    // SAFETY: off + 4 <= total.
    Some(u32::from_be(unsafe { core::ptr::read_unaligned(blob.add(off) as *const u32) }))
}

/// Is the NUL-terminated string at `blob + off` (inside `limit` bytes) equal
/// to `want`? Returns the offset just past its NUL on a match.
///
/// # Safety
/// `blob` must be readable for `limit` bytes.
#[inline(always)]
unsafe fn str_eq(blob: *const u8, limit: usize, off: usize, want: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    while i < want.len() {
        if off >= limit || limit - off <= i {
            return None;
        }
        // SAFETY: off + i < limit.
        if unsafe { *blob.add(off + i) } != want[i] {
            return None;
        }
        i += 1;
    }
    if off >= limit || limit - off <= i {
        return None;
    }
    // SAFETY: off + i < limit.
    if unsafe { *blob.add(off + i) } != 0 { None } else { Some(off + i + 1) }
}

/// Length of the NUL-terminated string at `blob + off`, counting the NUL,
/// or `None` if it runs past `limit`.
///
/// # Safety
/// `blob` must be readable for `limit` bytes.
#[inline(always)]
unsafe fn str_len(blob: *const u8, limit: usize, off: usize) -> Option<usize> {
    let mut i = off;
    while i < limit {
        // SAFETY: i < limit.
        if unsafe { *blob.add(i) } == 0 {
            return Some(i - off + 1);
        }
        i += 1;
    }
    None
}

/// The size of the flattened device tree at `blob`: its header's `totalsize`
/// capped at `max_bytes`, or `None` when the bytes are not a device tree. The
/// boot's overlap check (a tree inside the image is not touched) uses this
/// bound, not the window the tree happens to sit in.
///
/// # Safety
/// `blob` must be readable for 8 bytes, or for `max_bytes` if that is less.
#[inline(always)]
pub unsafe fn fdt_size(blob: *const u8, max_bytes: usize) -> Option<usize> {
    // SAFETY: bounded by `max_bytes`.
    unsafe {
        if be32(blob, max_bytes, 0)? != FDT_MAGIC {
            return None;
        }
        let t = be32(blob, max_bytes, 4)? as usize;
        Some(if t < max_bytes { t } else { max_bytes })
    }
}

/// Take the seeds a loader left in `/chosen` out of a flattened device tree:
/// `kaslr-seed` (8 bytes, the Linux arm64/riscv convention) and `rng-seed`
/// (any length, what U-Boot and OpenSBI add for the kernel's entropy pool).
/// Return the XOR of every 8-byte word of both and overwrite each property
/// with zeros in place, as Linux does, so the seed that placed the kernel is
/// not left in memory for anything that walks the tree later. `None` when the
/// blob is not a device tree, has neither property or only empty ones.
///
/// A tree damaged after a seed was taken still returns what was taken: the
/// property is already erased, so dropping the value would lose it.
///
/// # Safety
/// `blob` must be readable and writable for the `totalsize` its own header
/// declares, or for `max_bytes`, whichever is smaller; nothing else may
/// access it meanwhile.
#[inline(always)]
pub unsafe fn take_dt_seed(blob: *mut u8, max_bytes: usize) -> Option<u64> {
    // SAFETY: the caller's contract; `fdt_size` reads only the header.
    let total = unsafe { fdt_size(blob, max_bytes)? };
    let mut taken: Option<u64> = None;
    // SAFETY: `scan` stays inside `total`.
    let _ = unsafe { scan_chosen(blob, total, &mut taken) };
    taken
}

/// Walk the structure block; fold and erase the seeds of `/chosen` into
/// `taken`. `None` stops the walk early (end of the tree, or a damaged one);
/// what was taken before stays in `taken`.
///
/// # Safety
/// `blob` readable and writable for `total` bytes.
#[inline(always)]
unsafe fn scan_chosen(blob: *mut u8, total: usize, taken: &mut Option<u64>) -> Option<()> {
    // SAFETY (all reads below): bounded by `total`.
    let off_struct = unsafe { be32(blob, total, 8)? } as usize;
    let off_strings = unsafe { be32(blob, total, 12)? } as usize;
    if off_struct > total || off_strings > total {
        return None;
    }
    let mut p = off_struct;
    let mut depth = 0usize;
    // Inside the root's child "chosen" (and not in a node below it).
    let mut in_chosen = false;
    loop {
        let tok = unsafe { be32(blob, total, p)? };
        p += 4;
        match tok {
            FDT_BEGIN_NODE => {
                depth += 1;
                // The root (depth 1) has an empty name; "chosen" is its child. A node
                // below it must not end the match: its properties are not /chosen's.
                if depth == 2 {
                    in_chosen = unsafe { str_eq(blob, total, p, b"chosen") }.is_some();
                }
                let l = unsafe { str_len(blob, total, p)? };
                p = p.checked_add(l)?.checked_add(3)? & !3;
            }
            FDT_END_NODE => {
                if depth == 0 {
                    return None;
                }
                if depth == 2 && in_chosen {
                    // /chosen is done: both seeds are behind us.
                    return Some(());
                }
                depth -= 1;
            }
            FDT_PROP => {
                let len = unsafe { be32(blob, total, p)? } as usize;
                let nameoff = unsafe { be32(blob, total, p + 4)? } as usize;
                let data = p.checked_add(8)?;
                let next = data.checked_add(len)?.checked_add(3)? & !3;
                if next > total {
                    return None;
                }
                if in_chosen && depth == 2 {
                    let name = off_strings.checked_add(nameoff)?;
                    let is_kaslr = len == 8 && unsafe { str_eq(blob, total, name, b"kaslr-seed") }.is_some();
                    let is_rng = len != 0 && unsafe { str_eq(blob, total, name, b"rng-seed") }.is_some();
                    if is_kaslr || is_rng {
                        // Fold the property into 8 bytes (XOR of its words; the
                        // last, partial one zero-padded), then erase it.
                        let mut acc = 0u64;
                        let mut i = 0usize;
                        while i < len {
                            // SAFETY: data + len <= next <= total.
                            let b = unsafe { *blob.add(data + i) } as u64;
                            // kaslr-seed is a big-endian cell pair, so is the word order
                            // of the fold: byte i lands in bits 56 - 8 * (i % 8).
                            acc ^= b << (56 - 8 * (i % 8) as u32);
                            unsafe { *blob.add(data + i) = 0 };
                            i += 1;
                        }
                        *taken = Some(taken.unwrap_or(0) ^ acc);
                    }
                }
                p = next;
            }
            FDT_NOP => {}
            FDT_END => return None,
            _ => return None,
        }
    }
}
