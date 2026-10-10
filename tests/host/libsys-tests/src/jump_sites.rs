// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `crates/core/trace/src/jump.rs` (wave 15, static keys), pulled in by
//! `#[path]`: the site table and the two ISAs' patch encoders. The vectors
//! are words the assembler and linker produced in a built kernel (rv:
//! `j` = `jal zero`; arm: `b`), read back with llvm-objdump.

#[allow(dead_code)]
#[path = "../../../../crates/core/trace/src/jump.rs"]
mod jump;

use jump::*;

const RV: [(u64, u64, u32); 3] = [
    (0x8020_8cac, 0x8020_9324, 0x6780_006f),
    (0x8021_ef64, 0x8021_f632, 0x6ce0_006f),
    (0x802c_f02c, 0x802c_f0f2, 0x0c60_006f),
];
const A64: [(u64, u64, u32); 3] = [
    (0xffff_ff80_4008_8fb0, 0xffff_ff80_4008_9564, 0x1400_016d),
    (0xffff_ff80_4008_a284, 0xffff_ff80_4008_a544, 0x1400_00b0),
    (0xffff_ff80_4018_a0e8, 0xffff_ff80_4018_a574, 0x1400_0123),
];

#[test]
fn the_encoders_match_the_assembler() {
    for (site, target, word) in RV {
        assert_eq!(rv_jal(site, target), Some(word), "rv {site:#x}");
        assert_eq!(rv_jal_offset(word), Some(target as i64 - site as i64));
    }
    for (site, target, word) in A64 {
        assert_eq!(a64_b(site, target), Some(word), "a64 {site:#x}");
        assert_eq!(a64_b_offset(word), Some(target.wrapping_sub(site) as i64));
    }
}

#[test]
fn negative_and_extreme_offsets_round_trip() {
    for off in [-(1i64 << 20), -4096, -2, 2, 2046, (1 << 20) - 2] {
        let site = 0x8040_0000u64;
        let w = rv_jal(site, site.wrapping_add(off as u64)).expect("in range");
        assert_eq!(rv_jal_offset(w), Some(off));
    }
    for off in [-(1i64 << 27), -4, 4, (1 << 27) - 4] {
        let site = 0xffff_ff80_4800_0000u64;
        let w = a64_b(site, site.wrapping_add(off as u64)).expect("in range");
        assert_eq!(a64_b_offset(w), Some(off));
    }
}

#[test]
fn out_of_range_and_misaligned_offsets_are_refused() {
    let s = 0x8040_0000u64;
    assert_eq!(rv_jal(s, s + (1 << 20)), None);
    assert_eq!(rv_jal(s, s.wrapping_sub((1 << 20) + 2)), None);
    assert_eq!(rv_jal(s, s + 3), None, "odd offset");
    let a = 0xffff_ff80_4800_0000u64;
    assert_eq!(a64_b(a, a + (1 << 27)), None);
    assert_eq!(a64_b(a, a + 2), None, "not a multiple of 4");
}

#[test]
fn a_site_holds_its_nop_or_its_branch_and_nothing_else() {
    let rv = KeySite { site: RV[0].0, target: RV[0].1, key: 1, kind: KIND_RV_JAL };
    assert_eq!(rv.word(false), Ok(RV_NOP));
    assert_eq!(rv.word(true), Ok(RV[0].2));
    assert_eq!(rv.state(RV_NOP), Ok(false));
    assert_eq!(rv.state(RV[0].2), Ok(true));
    // Another site's branch, a compressed nop pair, an A64 nop: refused.
    assert_eq!(rv.state(RV[1].2), Err(SiteError::Unexpected));
    assert_eq!(rv.state(0x0001_0001), Err(SiteError::Unexpected));
    assert_eq!(rv.state(A64_NOP), Err(SiteError::Unexpected));
    let a = KeySite { site: A64[0].0, target: A64[0].1, key: 1, kind: KIND_A64_B };
    assert_eq!(a.word(false), Ok(A64_NOP));
    assert_eq!(a.state(A64[0].2), Ok(true));
    assert_eq!(a.state(RV_NOP), Err(SiteError::Unexpected));
    // A misaligned site (a compressed-assembled riscv64 site), an unknown
    // kind, a branch that cannot reach: refused before any word is chosen.
    assert_eq!(KeySite { site: RV[0].0 + 2, ..rv }.word(false), Err(SiteError::Misaligned));
    assert_eq!(KeySite { kind: 9, ..rv }.word(true), Err(SiteError::Kind));
    assert_eq!(KeySite { target: rv.site + (4 << 20), ..rv }.word(true), Err(SiteError::Range));
}

#[test]
fn the_table_parses_whole_entries_only() {
    let mut raw = Vec::new();
    for (i, (s, t, _)) in RV.iter().enumerate() {
        raw.extend_from_slice(&s.to_le_bytes());
        raw.extend_from_slice(&t.to_le_bytes());
        raw.extend_from_slice(&(i as u32).to_le_bytes());
        raw.extend_from_slice(&KIND_RV_JAL.to_le_bytes());
    }
    let sites: Vec<KeySite> = parse(&raw).expect("whole entries").collect();
    assert_eq!(sites.len(), 3);
    assert_eq!(sites[2], KeySite { site: RV[2].0, target: RV[2].1, key: 2, kind: KIND_RV_JAL });
    assert!(parse(&raw[..raw.len() - 1]).is_none());
}

// A64_PAN=probe boot-once sites: the linked `b` and the two `msr` words as
// the assembler emitted them in a built kernel (copy_to_user's window,
// llvm-objdump: `b` 0x1400000b at the site, `msr PAN, #0` d500409f and
// `msr PAN, #1` d500419f in its slow paths).
#[test]
fn a_pan_site_is_patched_to_the_assembler_s_msr_or_nop() {
    let clr = KeySite { site: 0xffff_ff80_401a_8590, target: 0xffff_ff80_401a_85bc, key: KEY_A64_PAN, kind: KIND_A64_PAN_CLR };
    let set = KeySite { site: 0xffff_ff80_401a_85ac, target: 0xffff_ff80_401a_85cc, key: KEY_A64_PAN, kind: KIND_A64_PAN_SET };
    assert_eq!(clr.pan_linked(), Ok(0x1400_000b));
    assert_eq!(set.pan_linked(), Ok(0x1400_0008));
    assert_eq!(clr.pan_word(true), Ok(0xd500_409f));
    assert_eq!(set.pan_word(true), Ok(0xd500_419f));
    assert_eq!(clr.pan_word(false), Ok(A64_NOP));
    assert_eq!(set.pan_word(false), Ok(A64_NOP));
    // Not a trace key: the trace patcher's encoders refuse it, and a trace
    // site is not a PAN site.
    assert_eq!(clr.word(true), Err(SiteError::Kind));
    let tr = KeySite { site: A64[0].0, target: A64[0].1, key: 1, kind: KIND_A64_B };
    assert_eq!(tr.pan_word(true), Err(SiteError::Kind));
    assert_eq!(tr.pan_linked(), Err(SiteError::Kind));
    assert!(KEY_A64_PAN >= 32);
}

// `SpinWait` alternative sites (N2b): the table carries the replacement in
// the low word and the linked word (0: a branch) in the high word. The
// words are from a built kernel (llvm-objdump --mattr=+zacas,+zawrs,+lse).
#[test]
fn an_alternative_site_reads_its_two_words() {
    // riscv64 `amocas.w.aq a1, s6, (a0)` linked as a `j`.
    let cas = KeySite { site: 0x8020_0000, target: 0x2d65_25af, key: KEY_SPIN_CAS, kind: KIND_RV_ALT };
    assert_eq!(cas.alt_word(), Ok(0x2d65_25af));
    assert_eq!(cas.alt_is_linked(RV[0].2), Ok(true), "a `jal zero` is the linked form");
    assert_eq!(cas.alt_is_linked(RV_NOP), Ok(false));
    assert_eq!(cas.alt_is_linked(0x2d65_25af), Ok(false), "the patched word is not the linked one");
    // riscv64 `wrs.nto` linked as the 4-byte nop.
    let wait = KeySite { site: 0x8020_0004, target: (RV_NOP as u64) << 32 | 0x00d0_0073,
                         key: KEY_SPIN_WAIT, kind: KIND_RV_ALT };
    assert_eq!(wait.alt_is_linked(RV_NOP), Ok(true));
    assert_eq!(wait.alt_is_linked(RV[0].2), Ok(false), "a branch is not this site's nop");
    // aarch64 `casa w19, w21, [x8]` linked as a `b`.
    let a = KeySite { site: 0xffff_ff80_4000_0000, target: 0x88f3_7d15, key: KEY_SPIN_CAS, kind: KIND_A64_ALT };
    assert_eq!(a.alt_is_linked(A64[0].2), Ok(true));
    assert_eq!(a.alt_is_linked(A64_NOP), Ok(false));
    // Misaligned and foreign kinds are refused.
    assert_eq!(KeySite { site: 0x8020_0002, ..cas }.alt_word(), Ok(0x2d65_25af), "rv: 2 mod 4 is a site");
    assert_eq!(KeySite { site: 0x8020_0001, ..cas }.alt_word(), Err(SiteError::Misaligned));
    assert_eq!(KeySite { site: 0xffff_ff80_4000_0002, ..a }.alt_word(), Err(SiteError::Misaligned));
    assert_eq!(KeySite { kind: KIND_RV_JAL, ..cas }.alt_word(), Err(SiteError::Kind));
}
