// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The pure halves of `cpu/cfi.rs`: the aarch64 key mix and `EnIA`, the
//! x86_64 `IA32_S_CET` word.

use crate::a64_cfi::{derive_key, isar0_has_rng, signing_on};
use crate::x86_cfi::{CR4_CET, IA32_S_CET, S_CET_ENDBR_EN, S_CET_KERNEL, S_CET_NO_TRACK_EN};

/// The key as the rows draw it. Under `key-canary` the counter is ignored, as
/// a mix that forgot an input would: the rows that move the counter must fail.
fn key(rng: [u64; 2], counter: u64, ids: u64, addr: u64) -> (u64, u64) {
    let counter = if cfg!(feature = "key-canary") { 0 } else { counter };
    derive_key(rng, counter, ids, addr)
}

const BASE: ([u64; 2], u64, u64, u64) = ([0x1111, 0x2222], 0xAAAA_0000_1234, 0x4100_D0B0_0000_0003, 0xFFFF_0000_0123_4000);

#[test]
fn every_key_source_moves_both_words() {
    let (rng, c, ids, addr) = BASE;
    let k0 = key(rng, c, ids, addr);
    let moved = [
        ("rng[0]", key([rng[0] ^ 1, rng[1]], c, ids, addr)),
        ("rng[1]", key([rng[0], rng[1] ^ 1], c, ids, addr)),
        ("counter", key(rng, c ^ 1, ids, addr)),
        ("ids", key(rng, c, ids ^ 1, addr)),
        ("addr", key(rng, c, ids, addr ^ 1)),
    ];
    for (what, k) in moved {
        assert_ne!(k.0, k0.0, "{what} leaves the low word alone");
        assert_ne!(k.1, k0.1, "{what} leaves the high word alone");
    }
}

#[test]
fn the_two_words_of_a_key_differ_and_the_mix_is_deterministic() {
    let (rng, c, ids, addr) = BASE;
    let k = key(rng, c, ids, addr);
    assert_ne!(k.0, k.1);
    assert_eq!(k, key(rng, c, ids, addr));
    // With no hardware RNG (both words 0) the key is still two different words.
    let k = key([0, 0], c, ids, addr);
    assert_ne!(k.0, k.1);
    assert_ne!(k.0, 0);
}

#[test]
fn consecutive_counter_values_do_not_give_nearby_keys() {
    let (rng, c, ids, addr) = BASE;
    let a = key(rng, c, ids, addr);
    let b = key(rng, c + 1, ids, addr);
    let flipped = (a.0 ^ b.0).count_ones() + (a.1 ^ b.1).count_ones();
    assert!(flipped >= 40, "a counter step moved only {flipped} of 128 key bits");
}

#[test]
fn rng_is_the_isar0_top_nibble() {
    assert!(isar0_has_rng(1 << 60));
    assert!(isar0_has_rng(0x2 << 60));
    assert!(!isar0_has_rng(!(0xf << 60)));
}

#[test]
fn ena_is_sctlr_bit_31_and_nothing_else_counts() {
    assert_eq!(crate::sysregs::SCTLR_EL1_ENIA, 1 << 31);
    assert!(signing_on(1 << 31));
    assert!(!signing_on(!(1u64 << 31)));
}

#[test]
fn the_x86_s_cet_word_is_the_documented_bits() {
    // SDM Vol. 4, IA32_S_CET: SH_STK_EN 0, WR_SHSTK_EN 1, ENDBR_EN 2, LEG_IW_EN 3, NO_TRACK_EN 4.
    assert_eq!(IA32_S_CET, 0x6A2);
    assert_eq!(S_CET_ENDBR_EN, 1 << 2);
    assert_eq!(S_CET_NO_TRACK_EN, 1 << 4);
    assert_eq!(S_CET_KERNEL, (1 << 2) | (1 << 4));
    assert_eq!(S_CET_KERNEL & 0b11, 0, "the kernel turns no shadow-stack bit on");
    assert_eq!(CR4_CET, 1 << 23);
}

#[test]
fn the_cr4_cet_bit_is_the_one_the_hwcap_reads() {
    let mmu = std::fs::read_to_string(crate::repo().join("crates/core/arch-x86_64/src/mmu.rs")).unwrap();
    assert!(mmu.contains("pub const CR4_CET: u64 = 1 << 23;"), "mmu.rs and cpu/cfi.rs disagree on CR4.CET");
}
