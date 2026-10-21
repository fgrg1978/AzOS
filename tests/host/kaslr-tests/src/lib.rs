// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for `azos_arch_api::kaslr`: the slide choice (alignment,
//! range, uniform coverage, every aarch64 granule), the policy outcomes, the
//! relocation walk on a synthetic image for each ISA's relative type, and the
//! device-tree seed. Each ISA's layout numbers and boot tables are tested in
//! the `*_layout` modules at the end (the real `mmu` sources, pulled in by
//! path).
//!
//! Run with:  cd tests/host/kaslr-tests && cargo test

#![cfg(test)]

use azos_arch_api::isa::ExtPolicy;
use azos_arch_api::kaslr::*;

mod elf;

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;


const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

/// The aarch64 4 KiB-granule layout: half of a 39-bit upper-half window,
/// 2 MiB blocks, one root slot (1 GiB) per table.
const A64_4K: Layout = Layout {
    window_start: 0xFFFF_FFC0_0000_0000, // OFFSET + 2^38
    window_bytes: 1 << 38,
    align: 2 * MIB,
    no_cross: GIB,
};

#[test]
fn layout_validity() {
    assert!(A64_4K.is_valid());
    assert!(!Layout { align: 3 * MIB, ..A64_4K }.is_valid(), "align must be a power of two");
    assert!(!Layout { no_cross: MIB, ..A64_4K }.is_valid(), "no_cross below align");
    assert!(!Layout { window_start: A64_4K.window_start + MIB, ..A64_4K }.is_valid(), "unaligned window");
    assert!(!Layout { window_bytes: 0, ..A64_4K }.is_valid());
}

#[test]
fn slide_is_inside_the_window_aligned_and_whole() {
    let bytes = 22 * MIB + 4096;
    let phase = 0x8_0000;
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    for _ in 0..10_000 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let s = pick_slide(&A64_4K, phase, bytes, seed ^ (seed >> 29)).unwrap();
        assert_eq!(s.image_va % A64_4K.align, phase, "VA and PA agree modulo the block");
        assert_eq!(s.block_va % A64_4K.align, 0);
        assert!(s.block_va >= A64_4K.window_start);
        let last = s.image_va + bytes - 1;
        assert!(last - A64_4K.window_start < A64_4K.window_bytes, "inside the window");
        assert_eq!(s.image_va / A64_4K.no_cross, last / A64_4K.no_cross, "one root slot");
        assert_eq!(s.blocks, (phase + bytes - 1) / A64_4K.align + 1);
    }
}

#[test]
fn extremes_of_the_entropy_reach_the_ends_of_the_window() {
    let bytes = 8 * MIB;
    let lo = pick_slide(&A64_4K, 0, bytes, 0).unwrap();
    assert_eq!(lo.image_va, A64_4K.window_start, "entropy 0 is the first slot");
    let slots = slide_slots(&A64_4K, 0, bytes);
    let hi = pick_slide(&A64_4K, 0, bytes, slots - 1).unwrap();
    // The last slot ends exactly at the last block of the window that fits.
    assert_eq!(
        hi.image_va as u128 + (hi.blocks * A64_4K.align) as u128,
        A64_4K.window_start as u128 + A64_4K.window_bytes as u128,
        "the last slot ends exactly at the top of the window"
    );
    // One more wraps to the first slot (modulo), never past the window.
    assert_eq!(pick_slide(&A64_4K, 0, bytes, slots).unwrap(), lo);
    let max = pick_slide(&A64_4K, 0, bytes, u64::MAX).unwrap();
    assert!(max.image_va >= A64_4K.window_start);
}

#[test]
fn distinct_entropy_gives_distinct_slots_and_uniform_coverage() {
    let bytes = 30 * MIB;
    let slots = slide_slots(&A64_4K, 0, bytes);
    assert_eq!(slots, 256 * (512 - 15 + 1), "256 root slots (GiB), 498 starts each");
    // Consecutive entropy values walk consecutive start blocks, then the next root slot.
    let a = pick_slide(&A64_4K, 0, bytes, 0).unwrap();
    let b = pick_slide(&A64_4K, 0, bytes, 1).unwrap();
    assert_eq!(b.image_va - a.image_va, A64_4K.align);
    let per = 512 - 15 + 1;
    let c = pick_slide(&A64_4K, 0, bytes, per).unwrap();
    assert_eq!(c.image_va, A64_4K.window_start + GIB, "the next root slot");
    assert_eq!(slide_bits(slots), 16);
}

#[test]
fn an_image_that_cannot_fit_is_refused() {
    assert_eq!(pick_slide(&A64_4K, 0, GIB + 1, 7), Err(SlideError::ImageTooLarge));
    assert_eq!(pick_slide(&A64_4K, 0, GIB, 7).unwrap().blocks, 512, "exactly one root slot is fine");
    // An offset into the first block that pushes the last byte over the slot.
    assert_eq!(pick_slide(&A64_4K, 2 * MIB - 1, GIB, 7), Err(SlideError::ImageTooLarge));
    assert_eq!(pick_slide(&A64_4K, 0, 0, 7), Err(SlideError::BadLayout));
    assert_eq!(pick_slide(&A64_4K, 2 * MIB, MIB, 7), Err(SlideError::BadLayout), "phase is below align");
    assert_eq!(pick_slide(&A64_4K, 0, u64::MAX, 7), Err(SlideError::ImageTooLarge), "no overflow");
    assert_eq!(slide_slots(&A64_4K, 0, GIB + 1), 0);
    assert_eq!(slide_bits(0), 0);
    assert_eq!(slide_bits(1), 0);
    assert_eq!(slide_bits(2), 1);
}

#[test]
fn every_aarch64_granule_has_room() {
    // 16 KiB: 39-bit range, 32 MiB blocks, 64 GiB root slots.
    let g16 = Layout { window_start: 0xFFFF_FFC0_0000_0000, window_bytes: 1 << 38, align: 32 * MIB, no_cross: 64 * GIB };
    // 64 KiB: 48-bit range, 512 MiB blocks, 4 TiB root slots.
    let g64 = Layout { window_start: 0xFFFF_8000_0000_0000, window_bytes: 1 << 47, align: 512 * MIB, no_cross: 4096 * GIB };
    for (l, name) in [(g16, "16K"), (g64, "64K")] {
        assert!(l.is_valid(), "{name}");
        let s = pick_slide(&l, 0x8_0000, 40 * MIB, 0xDEAD_BEEF_CAFE_F00D).unwrap();
        assert_eq!(s.image_va % l.align, 0x8_0000, "{name}");
        assert!(slide_bits(slide_slots(&l, 0x8_0000, 40 * MIB)) >= 12, "{name}: at least 12 bits");
    }
}

#[test]
fn the_policy_decides() {
    let l = A64_4K;
    let img = 20 * MIB;
    // Entropy: every allowed policy slides.
    for p in [ExtPolicy::Probe, ExtPolicy::Require] {
        assert!(matches!(decide(p, &l, 0, img, Some(5)), Outcome::Slide(_)));
    }
    // No entropy: probe keeps the link address, require refuses.
    assert_eq!(decide(ExtPolicy::Probe, &l, 0, img, None), Outcome::Unslid(Cause::NoEntropy));
    assert_eq!(decide(ExtPolicy::Require, &l, 0, img, None), Outcome::Refuse(Cause::NoEntropy));
    // An image that fits nowhere: the same split.
    assert_eq!(decide(ExtPolicy::Probe, &l, 0, 2 * GIB, Some(5)), Outcome::Unslid(Cause::NoSlot));
    assert_eq!(decide(ExtPolicy::Require, &l, 0, 2 * GIB, Some(5)), Outcome::Refuse(Cause::NoSlot));
    // Never does not slide even with entropy.
    assert!(matches!(decide(ExtPolicy::Never, &l, 0, img, Some(5)), Outcome::Unslid(_)));
    assert!(!Cause::NoEntropy.text().is_empty() && !Cause::NoSlot.text().is_empty());
}

#[test]
fn entropy_sources_mix() {
    assert_eq!(mix(None, None), None);
    assert_eq!(mix(Some(3), None), Some(3));
    assert_eq!(mix(None, Some(4)), Some(4));
    assert_eq!(mix(Some(0xF0), Some(0x0F)), Some(0xFF));
    assert_eq!(mix(Some(7), Some(7)), Some(0), "xor, by design: independence is assumed");
}

// ── relocations ────────────────────────────────────────────────────────

/// A synthetic image: 64 bytes at link address 0xFFFF_FF80_4008_0000 with
/// three pointer words, and the `.rela.dyn` that fixes them.
fn synthetic(ty: u32) -> (Vec<u8>, Vec<u8>, u64) {
    const LINK: u64 = 0xFFFF_FF80_4008_0000;
    let image = vec![0u8; 64];
    let mut rela = Vec::new();
    for (off, addend) in [(0u64, LINK + 0x100), (16, LINK + 0x20), (56, LINK + 0x3F)] {
        rela.extend_from_slice(&(LINK + off).to_le_bytes());
        rela.extend_from_slice(&(ty as u64).to_le_bytes());
        rela.extend_from_slice(&addend.to_le_bytes());
    }
    (image, rela, LINK)
}

fn word(image: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(image[at..at + 8].try_into().unwrap())
}

#[test]
fn relative_relocations_add_the_delta_on_each_isa() {
    for ty in [R_AARCH64_RELATIVE, R_RISCV_RELATIVE, R_X86_64_RELATIVE] {
        let (mut image, rela, link) = synthetic(ty);
        let delta = 0x0000_0040_0020_0000u64;
        let n = unsafe {
            apply_relative(rela.as_ptr(), rela.len(), image.as_mut_ptr(), image.len() as u64, link, delta, ty)
        };
        assert_eq!(n, Ok(3), "type {ty}");
        assert_eq!(word(&image, 0), link + 0x100 + delta);
        assert_eq!(word(&image, 16), link + 0x20 + delta);
        assert_eq!(word(&image, 56), link + 0x3F + delta);
        assert_eq!(word(&image, 8), 0, "a word no entry names is untouched");
    }
}

#[test]
fn a_zero_delta_still_writes_the_link_time_value() {
    // lld leaves a RELA target zero in place; an unslid boot must still
    // write the addend, so the walk is not skipped for delta 0.
    let (mut image, rela, link) = synthetic(R_AARCH64_RELATIVE);
    unsafe {
        apply_relative(rela.as_ptr(), rela.len(), image.as_mut_ptr(), 64, link, 0, R_AARCH64_RELATIVE).unwrap();
    }
    assert_eq!(word(&image, 0), link + 0x100);
}

#[test]
fn a_negative_delta_wraps() {
    let (mut image, rela, link) = synthetic(R_AARCH64_RELATIVE);
    let delta = (-(0x20_0000i64)) as u64;
    unsafe {
        apply_relative(rela.as_ptr(), rela.len(), image.as_mut_ptr(), 64, link, delta, R_AARCH64_RELATIVE).unwrap();
    }
    assert_eq!(word(&image, 0), link + 0x100 - 0x20_0000);
}

#[test]
fn a_symbol_relocation_is_refused_and_earlier_entries_stay_applied() {
    let (mut image, mut rela, link) = synthetic(R_AARCH64_RELATIVE);
    // Entry 1 becomes R_AARCH64_GLOB_DAT (1025).
    rela[24 + 8..24 + 16].copy_from_slice(&1025u64.to_le_bytes());
    let r = unsafe {
        apply_relative(rela.as_ptr(), rela.len(), image.as_mut_ptr(), 64, link, 1, R_AARCH64_RELATIVE)
    };
    assert_eq!(r, Err(RelocError::UnsupportedType { index: 1, ty: 1025 }));
    assert_eq!(word(&image, 0), link + 0x100 + 1, "entry 0 was applied");
    assert_eq!(word(&image, 16), 0, "entry 1 was not");
    // A symbol index in the high half of r_info does not make a RELATIVE one acceptable
    // (the type is the low 32 bits; a nonzero symbol with type RELATIVE still applies,
    // which is what the linker never emits - the table is checked by type only).
}

#[test]
fn out_of_image_and_malformed_tables_are_refused() {
    let (mut image, rela, link) = synthetic(R_AARCH64_RELATIVE);
    let ty = R_AARCH64_RELATIVE;
    // The last word starts at 56: an image of 63 bytes cannot hold it.
    let r = unsafe { apply_relative(rela.as_ptr(), rela.len(), image.as_mut_ptr(), 63, link, 0, ty) };
    assert_eq!(r, Err(RelocError::OutsideImage { index: 2 }));
    // An image whose link start is above the entries.
    let r = unsafe { apply_relative(rela.as_ptr(), rela.len(), image.as_mut_ptr(), 64, link + 8, 0, ty) };
    assert_eq!(r, Err(RelocError::OutsideImage { index: 0 }));
    // A table that is not a whole number of entries.
    let r = unsafe { apply_relative(rela.as_ptr(), rela.len() - 1, image.as_mut_ptr(), 64, link, 0, ty) };
    assert_eq!(r, Err(RelocError::TableSize));
    // An empty table applies nothing.
    let r = unsafe { apply_relative(rela.as_ptr(), 0, image.as_mut_ptr(), 64, link, 0, ty) };
    assert_eq!(r, Ok(0));
    // An offset so large that offset - link_start overflows a usize cast is still caught.
    let mut huge = rela.clone();
    huge[0..8].copy_from_slice(&u64::MAX.to_le_bytes());
    let r = unsafe { apply_relative(huge.as_ptr(), 24, image.as_mut_ptr(), 64, link, 0, ty) };
    assert_eq!(r, Err(RelocError::OutsideImage { index: 0 }));
}

// ── the device-tree seed ───────────────────────────────────────────────

/// A minimal FDT: / { chosen { kaslr-seed = <seed>; bootargs = "x"; }; soc { kaslr-seed = <8 bytes>; }; }
fn fdt(seed: u64, seed_len: u32, chosen_name: &str) -> Vec<u8> {
    fn be(v: u32) -> [u8; 4] { v.to_be_bytes() }
    let strings: &[u8] = b"kaslr-seed\0bootargs\0";
    let mut st: Vec<u8> = Vec::new();
    let begin = |st: &mut Vec<u8>, name: &str| {
        st.extend(be(FDT_BEGIN_NODE));
        st.extend(name.as_bytes());
        st.push(0);
        while st.len() % 4 != 0 { st.push(0); }
    };
    let prop = |st: &mut Vec<u8>, nameoff: u32, data: &[u8]| {
        st.extend(be(FDT_PROP));
        st.extend(be(data.len() as u32));
        st.extend(be(nameoff));
        st.extend(data);
        while st.len() % 4 != 0 { st.push(0); }
    };
    begin(&mut st, "");
    st.extend(be(FDT_NOP));
    begin(&mut st, "soc");
    prop(&mut st, 0, &0x1111_1111_1111_1111u64.to_be_bytes()); // a decoy outside /chosen
    st.extend(be(FDT_END_NODE));
    begin(&mut st, chosen_name);
    prop(&mut st, 11, b"x\0");
    let mut data = seed.to_be_bytes().to_vec();
    data.resize(seed_len as usize, 0);
    prop(&mut st, 0, &data);
    st.extend(be(FDT_END_NODE));
    st.extend(be(FDT_END_NODE));
    st.extend(be(FDT_END));
    let off_struct = 40u32;
    let off_strings = off_struct + st.len() as u32;
    let total = off_strings + strings.len() as u32;
    let mut b = Vec::new();
    for v in [FDT_MAGIC, total, off_struct, off_strings, 0 /* off_mem_rsvmap */, 17, 16, 0, strings.len() as u32, st.len() as u32] {
        b.extend(be(v));
    }
    b.extend(&st);
    b.extend(strings);
    b
}

#[test]
fn the_dt_seed_is_returned_and_erased() {
    let mut b = fdt(0x0123_4567_89AB_CDEF, 8, "chosen");
    let n = b.len();
    assert_eq!(unsafe { take_dt_seed(b.as_mut_ptr(), n) }, Some(0x0123_4567_89AB_CDEF));
    // Erased in place: asking again finds a zero seed (still "present"), not the old value.
    assert_eq!(unsafe { take_dt_seed(b.as_mut_ptr(), n) }, Some(0));
    assert!(!b.windows(8).any(|w| w == 0x0123_4567_89AB_CDEFu64.to_be_bytes()), "the seed is gone from memory");
    assert!(b.windows(8).any(|w| w == 0x1111_1111_1111_1111u64.to_be_bytes()), "the decoy was not touched");
}

#[test]
fn the_dt_seed_is_read_only_from_chosen_and_only_when_eight_bytes() {
    let mut b = fdt(5, 8, "chosen2"); // not /chosen
    let n = b.len();
    assert_eq!(unsafe { take_dt_seed(b.as_mut_ptr(), n) }, None);
    let mut b = fdt(5, 4, "chosen"); // 4 bytes
    let n = b.len();
    assert_eq!(unsafe { take_dt_seed(b.as_mut_ptr(), n) }, None);
    let mut b = fdt(5, 16, "chosen"); // 16 bytes
    let n = b.len();
    assert_eq!(unsafe { take_dt_seed(b.as_mut_ptr(), n) }, None);
}

#[test]
fn a_damaged_or_foreign_blob_gives_none_without_reading_outside_it() {
    // Not a device tree.
    let mut z = vec![0u8; 64];
    assert_eq!(unsafe { take_dt_seed(z.as_mut_ptr(), 64) }, None);
    // Every truncation of a good tree is None or the seed, never a crash.
    let good = fdt(0xAA, 8, "chosen");
    for cut in 0..good.len() {
        let mut b = good[..cut].to_vec();
        let _ = unsafe { take_dt_seed(b.as_mut_ptr(), cut) };
    }
    // The cap wins over a header that claims more than the caller owns.
    let mut b = good.clone();
    let cap = b.len() - 1;
    assert_eq!(unsafe { take_dt_seed(b.as_mut_ptr(), cap) }, Some(0xAA), "the seed lies before the cut");
    let mut b = good.clone();
    let cap = b.len() - 10; // cuts the name of the property
    assert_eq!(unsafe { take_dt_seed(b.as_mut_ptr(), cap) }, None, "a cut inside the strings hides the name");
    // Lengths designed to overflow offset arithmetic.
    let mut b = good.clone();
    b[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    let n = b.len();
    assert_eq!(unsafe { take_dt_seed(b.as_mut_ptr(), n) }, None);
    // Every word of the structure block replaced by 0xFFFFFFFF in turn.
    let mut b = good.clone();
    for i in 40..b.len().saturating_sub(4) {
        let saved: [u8; 4] = b[i..i + 4].try_into().unwrap();
        b[i..i + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        let n = b.len();
        let _ = unsafe { take_dt_seed(b.as_mut_ptr(), n) };
        b[i..i + 4].copy_from_slice(&saved);
    }
}


// ── the device-tree seeds, both properties ───────────────────────────────

/// / { chosen { <props> }; } with the given (name, data) properties.
fn fdt_props(props: &[(&str, &[u8])], chosen_name: &str) -> Vec<u8> {
    fn be(v: u32) -> [u8; 4] { v.to_be_bytes() }
    let mut strings: Vec<u8> = Vec::new();
    let mut offs = Vec::new();
    for (n, _) in props {
        offs.push(strings.len() as u32);
        strings.extend(n.as_bytes());
        strings.push(0);
    }
    let mut st: Vec<u8> = Vec::new();
    let begin = |st: &mut Vec<u8>, name: &str| {
        st.extend(be(FDT_BEGIN_NODE));
        st.extend(name.as_bytes());
        st.push(0);
        while st.len() % 4 != 0 { st.push(0); }
    };
    begin(&mut st, "");
    begin(&mut st, chosen_name);
    for (i, (_, data)) in props.iter().enumerate() {
        st.extend(be(FDT_PROP));
        st.extend(be(data.len() as u32));
        st.extend(be(offs[i]));
        st.extend(*data);
        while st.len() % 4 != 0 { st.push(0); }
    }
    st.extend(be(FDT_END_NODE));
    st.extend(be(FDT_END_NODE));
    st.extend(be(FDT_END));
    let off_struct = 40u32;
    let off_strings = off_struct + st.len() as u32;
    let total = off_strings + strings.len() as u32;
    let mut b = Vec::new();
    for v in [FDT_MAGIC, total, off_struct, off_strings, 0, 17, 16, 0, strings.len() as u32, st.len() as u32] {
        b.extend(be(v));
    }
    b.extend(&st);
    b.extend(&strings);
    b
}

#[test]
fn rng_seed_of_any_length_is_folded_and_erased() {
    // 32 bytes: the XOR of its four big-endian words.
    let rng: Vec<u8> = (1u8..=32).collect();
    let mut want = 0u64;
    for c in rng.chunks(8) {
        want ^= u64::from_be_bytes(c.try_into().unwrap());
    }
    let mut b = fdt_props(&[("rng-seed", &rng)], "chosen");
    let n = b.len();
    assert_eq!(unsafe { take_dt_seed(b.as_mut_ptr(), n) }, Some(want));
    assert!(!b.windows(8).any(|w| w == &rng[..8]), "the seed is gone from memory");
    assert_eq!(unsafe { take_dt_seed(b.as_mut_ptr(), n) }, Some(0), "erased: a second read finds zeros");
    // A length that is not a multiple of eight: the last word is zero-padded on the right.
    let odd = [0xAAu8, 0xBB, 0xCC];
    let mut b = fdt_props(&[("rng-seed", &odd)], "chosen");
    let n = b.len();
    assert_eq!(unsafe { take_dt_seed(b.as_mut_ptr(), n) }, Some(0xAABB_CC00_0000_0000));
    // An empty property is no seed.
    let mut b = fdt_props(&[("rng-seed", &[])], "chosen");
    let n = b.len();
    assert_eq!(unsafe { take_dt_seed(b.as_mut_ptr(), n) }, None);
}

#[test]
fn both_properties_are_taken_and_mixed() {
    let k = 0x0123_4567_89AB_CDEFu64.to_be_bytes();
    let r = 0xFF00_FF00_FF00_FF00u64.to_be_bytes();
    // Either order in the node.
    for props in [[("kaslr-seed", &k[..]), ("rng-seed", &r[..])], [("rng-seed", &r[..]), ("kaslr-seed", &k[..])]] {
        let mut b = fdt_props(&props, "chosen");
        let n = b.len();
        assert_eq!(unsafe { take_dt_seed(b.as_mut_ptr(), n) }, Some(0x0123_4567_89AB_CDEF ^ 0xFF00_FF00_FF00_FF00));
        assert!(!b.windows(8).any(|w| w == k || w == r), "both are erased");
    }
    // Only /chosen counts; a sibling of that name does not.
    let mut b = fdt_props(&[("rng-seed", &r[..])], "chosen2");
    let n = b.len();
    assert_eq!(unsafe { take_dt_seed(b.as_mut_ptr(), n) }, None);
    // A property after one that is seed-shaped but of the wrong length is still found.
    let mut b = fdt_props(&[("kaslr-seed", &k[..4]), ("rng-seed", &r[..])], "chosen");
    let n = b.len();
    assert_eq!(unsafe { take_dt_seed(b.as_mut_ptr(), n) }, Some(0xFF00_FF00_FF00_FF00));
}

#[test]
fn a_tree_damaged_after_the_seed_still_returns_what_was_erased() {
    let r = [7u8; 8];
    let want = u64::from_be_bytes(r);
    let good = fdt_props(&[("rng-seed", &r[..]), ("bootargs", b"x\0")], "chosen");
    let mut b = good.clone();
    let n = b.len();
    assert_eq!(unsafe { take_dt_seed(b.as_mut_ptr(), n) }, Some(want));
    // Every truncation: the seed is either still in memory (and the call may
    // say None) or erased, and then it must have been reported.
    let mut saw_erased = false;
    for cut in 0..good.len() {
        let mut t = good[..cut].to_vec();
        let had = t.windows(8).any(|w| w == r);
        let got = unsafe { take_dt_seed(t.as_mut_ptr(), cut) };
        let erased = had && !t.windows(8).any(|w| w == r);
        if erased {
            saw_erased = true;
            assert_eq!(got, Some(want), "cut {cut}: erased implies reported");
        }
    }
    assert!(saw_erased, "the property was complete in at least one truncation");
}

// ── plan, overlap, the table bounds ──────────────────────────────────────

#[test]
fn the_tree_is_measured_by_its_header_not_by_the_window() {
    let mut b = fdt(0xAA, 8, "chosen");
    let n = b.len();
    assert_eq!(unsafe { fdt_size(b.as_ptr(), 1 << 20) }, Some(n), "the header's totalsize");
    assert_eq!(unsafe { fdt_size(b.as_ptr(), 20) }, Some(20), "capped at what the caller owns");
    assert_eq!(unsafe { fdt_size(b.as_ptr(), 4) }, None, "too short for the header");
    b[0] ^= 1;
    assert_eq!(unsafe { fdt_size(b.as_ptr(), n) }, None, "not a device tree");
    // QEMU virt (aarch64): the tree at the base of DRAM, the Image 512 KiB above it. The window
    // the identity map gives the tree (the rest of the gigabyte) covers the image; the tree
    // itself does not, and that is the bound the overlap guard uses.
    let (dtb, img, image_bytes) = (0x4000_0000u64, 0x4008_0000u64, 30 * MIB);
    assert!(overlaps(dtb, GIB, img, image_bytes), "the window covers the image");
    assert!(!overlaps(dtb, n as u64, img, image_bytes), "the tree does not");
    // A tree that really does run into the image is refused.
    assert!(overlaps(img - 100, 4096, img, image_bytes));
}

#[test]
fn the_plan_follows_the_build_policy() {
    let link = 0xFFFF_FF80_4008_0000u64;
    let img = 0x4008_0000u64;
    let bytes = 30 * MIB;
    let r = plan(&A64_4K, link, img, bytes, Some(0x1234_5678_9ABC_DEF0));
    if POLICY.allowed() {
        let p = r.unwrap();
        assert_eq!(p.image_va % A64_4K.align, img % A64_4K.align);
        assert_eq!(p.delta, p.image_va.wrapping_sub(link));
        assert_eq!(p.bits, 16);
        assert_eq!(plan(&A64_4K, link, img, bytes, None).map(|p| p.delta == 0 && p.bits == 0 && p.image_va == link),
                   if POLICY == ExtPolicy::Require { Err(Cause::NoEntropy) } else { Ok(true) });
    } else {
        // n: the same call stays where it was linked, whatever the entropy.
        assert_eq!(r, Ok(Plan { delta: 0, image_va: link, bits: 0 }));
    }
    // An image that fits nowhere never slides.
    let big = plan(&A64_4K, link, img, 2 * GIB, Some(5));
    assert!(matches!(big, Ok(Plan { bits: 0, delta: 0, .. }) | Err(Cause::NoSlot)));
}

#[test]
fn ranges_overlap_only_when_they_share_a_byte() {
    assert!(overlaps(10, 5, 14, 5));
    assert!(overlaps(14, 5, 10, 5));
    assert!(!overlaps(10, 5, 15, 5), "adjacent");
    assert!(!overlaps(10, 0, 10, 5), "an empty range is nowhere");
    assert!(!overlaps(10, 5, 10, 0));
    assert!(overlaps(0, u64::MAX, 7, 1), "no overflow at the top");
    assert!(overlaps(u64::MAX - 1, 1000, u64::MAX - 5, 1000));
}

#[test]
fn a_table_outside_the_image_is_refused_before_any_write() {
    let (mut image, rela, link) = synthetic(R_AARCH64_RELATIVE);
    // The image is `image` (64 bytes at address `img`); the table lies in a separate buffer.
    let img = image.as_mut_ptr() as u64;
    let end = img + 64;
    let ty = R_AARCH64_RELATIVE;
    let t = rela.as_ptr() as u64;
    let r = unsafe { relocate_image(img, end, t, t + rela.len() as u64, link, 0, ty) };
    assert_eq!(r, Err(RelocError::TableOutsideImage), "a table that is not inside the image");
    assert!(image.iter().all(|&b| b == 0), "nothing was written");
    // Reversed and past-the-end bounds.
    assert_eq!(unsafe { relocate_image(img, end, img + 8, img, link, 0, ty) }, Err(RelocError::TableOutsideImage));
    assert_eq!(unsafe { relocate_image(img, end, img, end + 1, link, 0, ty) }, Err(RelocError::TableOutsideImage));
    assert_eq!(unsafe { relocate_image(end, img, end, end, link, 0, ty) }, Err(RelocError::TableOutsideImage));
    // An empty table inside the image: a link that lost `-pie`. Sliding it
    // would leave every pointer in data at the link address, so it is refused.
    assert_eq!(unsafe { relocate_image(img, end, img + 8, img + 8, link, 0, ty) }, Err(RelocError::EmptyTable));
    assert!(image.iter().all(|&b| b == 0), "nothing was written");
    // A table inside the image whose entries point outside it is caught per entry.
    let mut inner = vec![0u8; 24 + 64];
    let base = inner.as_mut_ptr() as u64;
    inner[0..8].copy_from_slice(&(link + 1000).to_le_bytes()); // target past the image
    inner[8..16].copy_from_slice(&(ty as u64).to_le_bytes());
    let r = unsafe { relocate_image(base, base + 88, base, base + 24, link, 0, ty) };
    assert_eq!(r, Err(RelocError::OutsideImage { index: 0 }));
    // And one that is fully inside applies.
    let mut ok = vec![0u8; 24 + 64];
    let base = ok.as_mut_ptr() as u64;
    ok[0..8].copy_from_slice(&(link + 40).to_le_bytes());
    ok[8..16].copy_from_slice(&(ty as u64).to_le_bytes());
    ok[16..24].copy_from_slice(&(link + 0x99).to_le_bytes());
    let r = unsafe { relocate_image(base, base + 88, base, base + 24, link, 5, ty) };
    assert_eq!(r, Ok(1));
    assert_eq!(word(&ok, 40), link + 0x99 + 5);
}

#[test]
fn every_failure_says_why() {
    for f in [
        Failure::Refused(Cause::NoEntropy),
        Failure::Refused(Cause::NoSlot),
        Failure::Relocation(RelocError::TableSize),
        Failure::Relocation(RelocError::TableOutsideImage),
        Failure::Relocation(RelocError::EmptyTable),
    ] {
        let t = f.text();
        assert!(t.starts_with(b"\r\n[KASLR] FATAL:") && t.ends_with(b"\r\n"), "{f:?}");
    }
    // The link that lost `-pie` is named as such, not as a corrupt table.
    let empty = Failure::Relocation(RelocError::EmptyTable).text();
    assert!(empty.windows(19).any(|w| w == b"no relocation table"));
    assert_ne!(empty, Failure::Relocation(RelocError::TableSize).text());
}

// ── the aarch64 layout ─────────────────────────────────────────────────────
//
// `crates/core/arch-aarch64/src/mmu/mod.rs` is pure arithmetic and pulled by
// path, as the other aarch64 host suites do; its `kaslr` submodule is the code
// under test.
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-aarch64/src/mmu/mod.rs"]
mod aarch64_mmu;

mod aarch64_layout {
    use super::*;
    use crate::aarch64_mmu::kaslr as a64;
    use crate::aarch64_mmu::{Granule, GRANULE_16K, GRANULE_4K, GRANULE_64K};

    const GRANULES: [(Granule, &str); 3] = [(GRANULE_4K, "4K"), (GRANULE_16K, "16K"), (GRANULE_64K, "64K")];

    #[test]
    fn the_layout_matches_the_documented_table() {
        let l4 = a64::layout_for(GRANULE_4K);
        assert_eq!(l4, A64_4K, "the shared tests' 4 KiB layout is the real one");
        let l16 = a64::layout_for(GRANULE_16K);
        assert_eq!((l16.window_bytes, l16.align, l16.no_cross), (256 * GIB, 32 * MIB, 64 * GIB));
        let l64 = a64::layout_for(GRANULE_64K);
        assert_eq!((l64.window_bytes, l64.align, l64.no_cross), (128 * 1024 * GIB, 512 * MIB, 4096 * GIB));
        for (g, name) in GRANULES {
            let l = a64::layout_for(g);
            assert!(l.is_valid(), "{name}");
            let off = g.kernel_va_offset();
            assert_eq!(l.window_start, off + (1u64 << (g.va_bits - 1)), "{name}: the upper half of the range");
            assert_eq!(l.window_start as u128 + l.window_bytes as u128, 1u128 << 64, "{name}: to the top of the address space");
            // The linear map reaches `pa | off` for pa below the window size, so the two never meet.
            assert!((off | (l.window_bytes - 1)) < l.window_start, "{name}: the linear map ends below the window");
        }
    }

    #[test]
    fn the_build_uses_the_layout_of_its_granule() {
        assert_eq!(a64::LAYOUT, a64::layout_for(crate::aarch64_mmu::GRANULE));
        assert_eq!(a64::IMAGE_REGION_BASE, a64::LAYOUT.window_start);
        assert_eq!(a64::IMAGE_REGION_BASE, crate::aarch64_mmu::KERNEL_VA_OFFSET + a64::LINEAR_MAP_BYTES);
    }

    /// A slid image: the block map (`image_blocks`) covers every byte of the
    /// image with the same VA-to-PA relation the image bias gives.
    #[test]
    fn the_block_map_translates_every_image_byte_as_the_bias_does() {
        let img_pa = 0x4008_0000u64; // QEMU virt: 512 KiB into DRAM
        for (g, name) in GRANULES {
            let l = a64::layout_for(g);
            let bytes = 36 * MIB + 0x1234 * 4096;
            for seed in [0u64, 1, 0xDEAD_BEEF, u64::MAX / 3, u64::MAX] {
                let phase = img_pa & (l.align - 1);
                let s = pick_slide(&l, phase, bytes, seed).unwrap();
                let (va_block, pa_block, blocks) = image_blocks(&l, s.image_va, img_pa, bytes);
                assert_eq!(blocks, s.blocks, "{name}: the slide and the map agree on the block count");
                assert_eq!(va_block, s.block_va, "{name}");
                assert_eq!(va_block % l.align, 0);
                assert_eq!(pa_block % l.align, 0);
                let bias = s.image_va.wrapping_sub(img_pa);
                for off in [0, 1, bytes / 2, bytes - 1] {
                    let va = s.image_va + off;
                    let pa = img_pa + off;
                    let blk = (va - va_block) / l.align;
                    assert!(blk < blocks, "{name}: byte {off} is inside the mapped blocks");
                    assert_eq!(pa_block + blk * l.align + (va - va_block) % l.align, pa, "{name}: block map = bias");
                    assert_eq!(a64::kva_to_pa_for(g, va, bias), pa, "{name}: kva_to_pa of a slid image address");
                }
                // The whole mapped range is inside one root entry (one level-2 table).
                let last = va_block.wrapping_add(blocks * l.align).wrapping_sub(1); // may end exactly at 2^64
                assert_eq!(va_block / l.no_cross, last / l.no_cross, "{name}");
            }
        }
    }

    #[test]
    fn linear_map_and_unslid_addresses_convert_by_clearing_the_offset() {
        let off = crate::aarch64_mmu::KERNEL_VA_OFFSET;
        let bias = 0xFFFF_FFC1_2345_6000u64.wrapping_sub(0x4008_0000);
        assert_eq!(a64::kva_to_pa_for(GRANULE_4K, off | 0x4020_1000, bias), 0x4020_1000, "a linear-map VA");
        assert_eq!(a64::kva_to_pa_for(GRANULE_4K, 0x4020_1000, bias), 0x4020_1000, "an address already physical");
        // The unslid image sits in the linear map: its VA is `pa | off` and converts the same way.
        assert_eq!(a64::kva_to_pa_for(GRANULE_4K, off | 0x4008_0000, off), 0x4008_0000);
        // The first address of the image window is an image address.
        assert_eq!(a64::kva_to_pa_for(GRANULE_4K, a64::IMAGE_REGION_BASE, a64::IMAGE_REGION_BASE - 0x4008_0000), 0x4008_0000);
    }

    #[test]
    fn a_build_with_the_policy_n_has_no_image_window() {
        // The layer is present exactly when the host .config allows a slide
        // (KASLR_AVAILABLE and a policy other than n). Nothing has booted here,
        // so the image is unslid either way; only the window differs.
        let off = crate::aarch64_mmu::KERNEL_VA_OFFSET;
        assert!(!a64::image_slid());
        assert_eq!(a64::image_bias(), off);
        assert_eq!(a64::is_image_va(a64::IMAGE_REGION_BASE + 5), a64::ENABLED);
        if !a64::ENABLED {
            // Absent layer: every conversion is the single-offset arithmetic.
            assert_eq!(a64::kva_to_pa(off | 0x4000_1000), 0x4000_1000);
        }
    }
}

// ── the riscv64 layout and boot root ──────────────────────────────────────
//
// `crates/core/arch-riscv64/src/mmu.rs` is pure Sv39 arithmetic and pulled by
// path, as `tests/host/arch-tests` does; its `kaslr` submodule is the code
// under test (the boot half, `kaslr_boot`, is bare-metal only).
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-riscv64/src/mmu.rs"]
mod riscv_mmu;

mod riscv64_layout {
    use super::*;
    use crate::riscv_mmu::kaslr as rv;

    #[test]
    fn the_window_is_the_sv39_upper_half() {
        assert!(rv::LAYOUT.is_valid());
        assert_eq!(rv::LAYOUT.window_start, 0xFFFF_FFC0_0000_0000, "VPN[2] 256");
        assert_eq!(rv::LAYOUT.window_start.wrapping_add(rv::LAYOUT.window_bytes), 0, "to the top of the address space");
        assert_eq!(rv::LAYOUT.align, 2 * MIB, "one level-1 megapage");
        assert_eq!(rv::LAYOUT.no_cross, GIB, "one root entry, one level-1 table");
        // Canonical: bit 38 sign-extended to the top. The first and last VAs of the window.
        for va in [rv::LAYOUT.window_start, u64::MAX - 4095] {
            assert_eq!(va >> 38, (1u64 << 26) - 1, "{va:#x} is canonical in the upper half");
            assert!(rv::vpn2(va) >= 256);
            assert_eq!(rv::vpn2(va), riscv_mmu::vpn2(va as usize));
        }
        assert_eq!(rv::vpn2(rv::LAYOUT.window_start), 256);
        assert_eq!(rv::vpn2(u64::MAX), 511);
    }

    #[test]
    fn sixteen_bits_for_a_thirty_mib_image() {
        let bytes = 30 * MIB;
        // QEMU virt (0x8020_0000), VF2 (0x4020_0000) and K1 (0x20_0000) all load 2 MiB-aligned.
        for pa in [0x8020_0000u64, 0x4020_0000, 0x20_0000] {
            let phase = pa & (rv::LAYOUT.align - 1);
            let slots = slide_slots(&rv::LAYOUT, phase, bytes);
            assert_eq!(slots, 256 * (512 - 15 + 1), "{pa:#x}");
            assert_eq!(slide_bits(slots), 16);
            for seed in [0u64, 1, 0xDEAD_BEEF_CAFE_F00D, u64::MAX] {
                let s = pick_slide(&rv::LAYOUT, phase, bytes, seed).unwrap();
                assert!(rv::is_image_va(s.image_va) || !rv::ENABLED);
                assert!(s.image_va >= rv::IMAGE_REGION_BASE);
                assert_eq!(s.image_va % rv::LAYOUT.align, phase);
            }
        }
    }

    #[test]
    fn the_boot_root_maps_ram_1_to_1_and_the_image_at_its_base() {
        let pa = 0x8020_0000u64;
        let bytes = 30 * MIB + 0x2000;
        let seed = 0xA5A5_5A5A_1234_8765u64;
        let s = pick_slide(&rv::LAYOUT, pa & (rv::LAYOUT.align - 1), bytes, seed).unwrap();
        let (va_block, pa_block, blocks) = image_blocks(&rv::LAYOUT, s.image_va, pa, bytes);
        assert_eq!((va_block, blocks), (s.block_va, s.blocks));
        let mut root = [0u64; 512];
        let mut l1 = [0u64; 512];
        let l1_pa = 0x8123_4000u64;
        let n = rv::fill_boot_root(&mut root, &mut l1, l1_pa, va_block, pa_block, blocks);
        assert_eq!(n, blocks, "every block written");

        // Walk it the way the hardware does (Sv39), for an address in the low half and the image.
        let walk = |va: u64| -> Option<u64> {
            let r = root[((va >> 30) & 0x1FF) as usize];
            if r & 1 == 0 { return None; }
            if r & 0xE != 0 {
                // gigapage leaf: X only where the image's frames are
                let code = (va >> 30) == (pa >> 30);
                assert_eq!(r & 0xFF, if code { rv::BOOT_LEAF } else { rv::BOOT_DATA_LEAF }, "{va:#x}: leaf bits");
                return Some(((r >> 10) << 12) + (va & (GIB - 1)));
            }
            assert_eq!(((r >> 10) << 12), l1_pa, "the root entry names the level-1 table");
            assert_eq!(r & 0x3FF, rv::PTE_V, "a non-leaf PTE is V alone");
            let l = l1[((va >> 21) & 0x1FF) as usize];
            if l & 1 == 0 { return None; }
            assert_eq!(l & 0xFF, rv::BOOT_LEAF);
            Some(((l >> 10) << 12) + (va & (2 * MIB - 1)))
        };
        // RAM and devices: 1:1 over the whole low half.
        for a in [0x0u64, 0x1000_0000, 0x8000_0000, pa, 0x20_0000_0000, 0x3F_FFFF_F000] {
            assert_eq!(walk(a), Some(a), "{a:#x}");
        }
        // The image: every byte translates as the bias does.
        let bias = s.image_va.wrapping_sub(pa);
        for off in [0, 1, 0x1000, bytes / 2, bytes - 1] {
            assert_eq!(walk(s.image_va + off), Some(pa + off), "image +{off:#x}");
            assert_eq!(s.image_va + off - bias, pa + off);
        }
        // Just outside the image's blocks in the window: unmapped.
        assert_eq!(walk(va_block + blocks * rv::LAYOUT.align), None);
        assert_eq!(walk(va_block.wrapping_sub(rv::LAYOUT.align)), None);
        // The low half has no entry at all in the upper half but the image's.
        assert_eq!(root.iter().skip(256).filter(|&&e| e != 0).count(), 1);
        assert_eq!(root.iter().take(256).filter(|&&e| e != 0).count(), 256);
    }

    #[test]
    fn only_the_gigapages_that_hold_the_image_are_executable() {
        // An image across a gigapage boundary needs both executable; nothing else is.
        let pa = 0x7FF0_0000u64;
        let bytes = 30 * MIB;
        let s = pick_slide(&rv::LAYOUT, pa & (rv::LAYOUT.align - 1), bytes, 3).unwrap();
        let (va_block, pa_block, blocks) = image_blocks(&rv::LAYOUT, s.image_va, pa, bytes);
        let mut root = [0u64; 512];
        let mut l1 = [0u64; 512];
        rv::fill_boot_root(&mut root, &mut l1, 0x8000_0000, va_block, pa_block, blocks);
        let exec: Vec<usize> = (0..256).filter(|&i| root[i] & 8 != 0).collect();
        assert_eq!(exec, vec![1, 2], "the gigapages of [0x7ff00000, +30 MiB)");
        for i in 0..256 {
            assert_eq!(root[i] & 0xFF, if exec.contains(&i) { rv::BOOT_LEAF } else { rv::BOOT_DATA_LEAF });
        }
    }

    #[test]
    fn satp_and_pte_words() {
        assert_eq!(rv::boot_satp(0x8123_4000), (8u64 << 60) | 0x8_1234, "Sv39, ASID 0, PPN of the root");
        assert_eq!(rv::boot_satp(0x8123_4000) as usize, riscv_mmu::make_satp(0x8123_4000, 0));
        assert_eq!(rv::table_pte(0x8123_4000), (0x8_1234u64 << 10) | 1);
        assert_eq!(rv::mega_pte(0x8020_0000), (0x8_0200u64 << 10) | rv::BOOT_LEAF);
        // The encoders agree with the kernel's own PTE type.
        let kern = riscv_mmu::Pte::new(0x8020_0000, riscv_mmu::PteFlags::KERNEL_RWX);
        assert_eq!(rv::mega_pte(0x8020_0000), kern.bits());
        assert_eq!(rv::boot_gigapage(2, true), riscv_mmu::Pte::new(0x8000_0000, riscv_mmu::PteFlags::KERNEL_RWX).bits());
        assert_eq!(rv::boot_gigapage(2, false), riscv_mmu::Pte::new(0x8000_0000, riscv_mmu::PteFlags::KERNEL_RW).bits());
    }

    #[test]
    fn a_table_that_would_overflow_is_not_written_past() {
        let mut root = [0u64; 512];
        let mut l1 = [0u64; 512];
        // 600 blocks from entry 100: the table holds 412.
        let n = rv::fill_boot_root(&mut root, &mut l1, 0x1000, 100 * 2 * MIB, 0x8000_0000, 600);
        assert_eq!(n, 412);
        assert_eq!(l1[511], rv::mega_pte(0x8000_0000 + 411 * 2 * MIB));
    }

    #[test]
    fn without_a_slide_every_conversion_is_the_identity() {
        // The host build's policy is n (or a non-slid boot): bias 0, identity.
        assert!(!rv::image_slid());
        assert_eq!(rv::image_bias(), 0);
        assert_eq!(rv::image_phys(0x8020_1000), 0x8020_1000);
        assert_eq!(rv::phys_of(0x8020_1000), 0x8020_1000);
        assert_eq!(rv::phys_of(0xFFFF_FFC1_2345_6000), if rv::ENABLED { 0xFFFF_FFC1_2345_6000 } else { 0xFFFF_FFC1_2345_6000 });
    }
}

// ── the x86_64 layout and the image page directory ───────────────────────
//
// `crates/core/arch-x86_64/src/mmu.rs` is pure paging arithmetic and pulled by
// path; `kaslr` is the code under test.
#[allow(dead_code)]
#[path = "../../../../crates/core/arch-x86_64/src/mmu.rs"]
mod x86_mmu;

mod x86_64_layout {
    use super::*;
    use crate::x86_mmu::kaslr as x;
    use crate::x86_mmu::{fill_image_map, image_phys_with, KERNEL_VA_OFFSET};

    #[test]
    fn the_window_is_the_first_gib_of_the_top_two() {
        assert!(x::LAYOUT.is_valid());
        assert_eq!(x::LAYOUT.window_start, KERNEL_VA_OFFSET);
        assert_eq!(x::LAYOUT.window_bytes, GIB, "the AP start tables map one GiB of image");
        assert_eq!(x::LAYOUT.align, 2 * MIB);
        assert_eq!(x::LAYOUT.no_cross, GIB, "one page directory");
        assert_eq!(x::LAYOUT.window_bytes, crate::x86_mmu::IMAGE_WINDOW);
        // -mcmodel=kernel: the whole image, whatever the slide, stays in the top 2 GiB.
        assert!(x::LAYOUT.window_start as i64 >= -(2i64 << 30));
    }

    #[test]
    fn about_eight_bits_for_a_thirty_mib_image() {
        let pa = 0x10_1000u64; // _text_start: 1 MiB + the note's page
        let phase = pa & (x::LAYOUT.align - 1);
        let bytes = 30 * MIB;
        let slots = slide_slots(&x::LAYOUT, phase, bytes);
        // 512 starts minus the 16 blocks (phase + 30 MiB = 31 MiB + 4 KiB) plus one.
        assert_eq!(slots, 512 - 16 + 1);
        assert_eq!(slide_bits(slots), 8);
        for seed in [0u64, 1, 0xDEAD_BEEF, u64::MAX] {
            let s = pick_slide(&x::LAYOUT, phase, bytes, seed).unwrap();
            assert!(s.image_va >= x::IMAGE_REGION_BASE);
            assert!(s.image_va + bytes - x::IMAGE_REGION_BASE <= GIB, "the whole image inside the first GiB");
            assert_eq!(s.image_va % x::LAYOUT.align, phase);
        }
    }

    #[test]
    fn a_virtual_slide_is_a_negative_recorded_slide_and_translates_back() {
        let pa = 0x10_1000u64;
        let link = KERNEL_VA_OFFSET + pa;
        let bytes = 30 * MIB;
        let phase = pa & (x::LAYOUT.align - 1);
        for seed in [0u64, 7, 0xFEED_FACE, u64::MAX] {
            let s = pick_slide(&x::LAYOUT, phase, bytes, seed).unwrap();
            let slide = x::recorded_slide(s.image_va - link);
            for off in [0, 4096, bytes / 2, bytes - 1] {
                assert_eq!(image_phys_with(s.image_va + off, slide), pa + off, "seed {seed:#x} +{off:#x}");
            }
        }
        // No slide: 0.
        assert_eq!(x::recorded_slide(0), 0);
    }

    #[test]
    fn the_image_page_directory_maps_every_byte_onto_its_frame() {
        let pa = 0x10_1000u64;
        let bytes = 30 * MIB;
        let phase = pa & (x::LAYOUT.align - 1);
        let s = pick_slide(&x::LAYOUT, phase, bytes, 0xC0FFEE).unwrap();
        let (first, pa_block) = x::first_block(s.image_va, pa);
        let (va_block, pa_block2, blocks) = image_blocks(&x::LAYOUT, s.image_va, pa, bytes);
        assert_eq!(pa_block, pa_block2);
        assert_eq!(first as u64 * 2 * MIB, va_block - x::IMAGE_REGION_BASE);
        let mut pd = [0u64; 512];
        assert_eq!(x::fill_image_pd(&mut pd, first, pa_block, blocks), blocks);
        for off in [0, 1, 4096, bytes / 3, bytes - 1] {
            let va = s.image_va + off;
            let e = pd[((va - x::IMAGE_REGION_BASE) >> 21) as usize];
            assert_eq!(e & 0x87, 0x83, "P | RW | PS, no user bit, no NX");
            let got = (e & !0x1FFFFF & ((1 << 48) - 1)) + (va & (2 * MIB - 1));
            assert_eq!(got, pa + off, "+{off:#x}");
        }
        // Nothing mapped outside the image's blocks.
        assert_eq!(pd.iter().filter(|&&e| e != 0).count() as u64, blocks);
        assert_eq!(pd[first - 1 + usize::from(first == 0)] == 0 || first == 0, true);
    }

    #[test]
    fn the_ap_tables_follow_the_slid_image() {
        // `smp::build_image_map` over a slid range: 4 KiB leaves onto the same frames.
        let pa = 0x10_1000u64;
        let bytes = 8 * MIB;
        let phase = pa & (x::LAYOUT.align - 1);
        let s = pick_slide(&x::LAYOUT, phase, bytes, 99).unwrap();
        let slide = x::recorded_slide(s.image_va - (KERNEL_VA_OFFSET + pa));
        let mut pd = [0u64; 512];
        let mut pts = vec![[0u64; 512]; 6];
        let used = fill_image_map(&mut pd, &mut pts, |k| 0x4000_0000 + 4096 * k as u64, s.image_va, s.image_va + bytes, slide)
            .unwrap();
        assert!(used >= 4 && used <= 6);
        let va = s.image_va + 5 * MIB + 123 * 4096;
        let slot = ((va - x::IMAGE_REGION_BASE) >> 21) as usize;
        let table = ((pd[slot] & !0xFFF) - 0x4000_0000) / 4096;
        let pte = pts[table as usize][((va >> 12) & 511) as usize];
        assert_eq!(pte & !0xFFF, (pa + 5 * MIB + 123 * 4096) & !0xFFF, "the AP map and the boot map agree");
    }

    #[test]
    fn a_pd_that_would_overflow_is_not_written_past() {
        let mut pd = [0u64; 512];
        assert_eq!(x::fill_image_pd(&mut pd, 500, 0x20_0000, 40), 12);
        assert_eq!(pd[511] & 0x83, 0x83);
    }

    #[test]
    fn without_a_slide_nothing_is_reported_slid() {
        assert!(!x::image_slid());
        assert_eq!(x::slide_bits(), 0);
        assert_eq!(x::seed_sources(), 0);
    }
}
