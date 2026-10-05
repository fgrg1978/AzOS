// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `crates/core/lx-loader` (RFC-0053 stage L0b).
//!
//! Two independent oracles:
//!
//! * **Encoders vs llvm-mc.** Every instruction-field encoder is checked
//!   against encodings produced by `llvm-mc --show-encoding` (LLVM 22) and
//!   pasted here as constants: the zero-immediate instruction is the input,
//!   the assembled instruction with the immediate is the expected output.
//! * **Whole modules vs a decoder.** `build/lx/lxtest-{riscv64,aarch64}.ko`
//!   (`make lx-modules`) are loaded at chosen bases, and every relocation in
//!   them is checked by DECODING the patched field and comparing it with the
//!   psABI formula, computed here from this file's own ELF reader. The
//!   loader's relocation code is not reused by the oracle.

#![cfg(test)]

use azos_lx_loader::{admit, encode, license_is_gpl_compatible, Error, Isa, Module, Region};
use std::collections::BTreeMap;

// ── fixtures ────────────────────────────────────────────────────────────────

fn ko(isa: Isa) -> Vec<u8> {
    let name = match isa {
        Isa::Riscv64 => "lxtest-riscv64.ko",
        Isa::Aarch64 => "lxtest-aarch64.ko",
    };
    let path = format!("{}/../../../build/lx/{}", env!("CARGO_MANIFEST_DIR"), name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e} -- run `make lx-modules` in the repo root"))
}

const MIX: u64 = 0x1000_2000;
const LOG: u64 = 0x1000_3000;

fn resolver(name: &[u8]) -> Option<u64> {
    match name {
        b"lx_test_mix" => Some(MIX),
        b"lx_test_log" => Some(LOG),
        _ => None,
    }
}

// ── an independent ELF reader (the oracle's, not the loader's) ─────────────

fn u16le(b: &[u8], o: usize) -> u16 { u16::from_le_bytes(b[o..o + 2].try_into().unwrap()) }
fn u32le(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }
fn u64le(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }

struct Sh { name: String, kind: u32, flags: u64, off: usize, size: usize, link: usize, info: usize }
struct Rel { off: u64, sym: usize, kind: u32, addend: i64, section: usize }
struct Sy { name: String, shndx: u16, value: u64 }

fn read_elf(b: &[u8]) -> (Vec<Sh>, Vec<Sy>, Vec<Rel>) {
    let shoff = u64le(b, 40) as usize;
    let shnum = u16le(b, 60) as usize;
    let shstr = u16le(b, 62) as usize;
    let raw: Vec<(u32, u32, u64, usize, usize, usize, usize)> = (0..shnum)
        .map(|i| {
            let o = shoff + i * 64;
            (u32le(b, o), u32le(b, o + 4), u64le(b, o + 8), u64le(b, o + 24) as usize,
             u64le(b, o + 32) as usize, u32le(b, o + 40) as usize, u32le(b, o + 44) as usize)
        })
        .collect();
    let cstr = |base: usize, off: usize| -> String {
        let s = &b[base + off..];
        String::from_utf8_lossy(&s[..s.iter().position(|&c| c == 0).unwrap()]).into_owned()
    };
    let shs: Vec<Sh> = raw
        .iter()
        .map(|r| Sh { name: cstr(raw[shstr].3, r.0 as usize), kind: r.1, flags: r.2, off: r.3, size: r.4, link: r.5, info: r.6 })
        .collect();
    let st = shs.iter().find(|s| s.kind == 2).unwrap();
    let strtab = shs[st.link].off;
    let syms: Vec<Sy> = (0..st.size / 24)
        .map(|i| {
            let o = st.off + i * 24;
            Sy { name: cstr(strtab, u32le(b, o) as usize), shndx: u16le(b, o + 6), value: u64le(b, o + 8) }
        })
        .collect();
    let mut rels = Vec::new();
    for s in shs.iter().filter(|s| s.kind == 4) {
        for k in 0..s.size / 24 {
            let o = s.off + k * 24;
            let info = u64le(b, o + 8);
            rels.push(Rel { off: u64le(b, o), sym: (info >> 32) as usize, kind: info as u32, addend: u64le(b, o + 16) as i64, section: s.info });
        }
    }
    (shs, syms, rels)
}

fn sext(v: u64, bits: u32) -> i64 {
    ((v << (64 - bits)) as i64) >> (64 - bits)
}

// ── riscv64 decoders ────────────────────────────────────────────────────────

fn rv_u_imm(i: u32) -> i64 { sext((i >> 12) as u64, 20) << 12 }
fn rv_i_imm(i: u32) -> i64 { sext((i >> 20) as u64, 12) }
fn rv_s_imm(i: u32) -> i64 { sext((((i >> 25) << 5) | ((i >> 7) & 0x1f)) as u64, 12) }

// ── aarch64 decoders ────────────────────────────────────────────────────────

fn a64_imm26(i: u32) -> i64 { sext((i & 0x03ff_ffff) as u64, 26) << 2 }
fn a64_adr(i: u32) -> i64 { sext(((((i >> 5) & 0x7ffff) << 2) | ((i >> 29) & 3)) as u64, 21) }
fn a64_imm12(i: u32) -> u64 { ((i >> 10) & 0xfff) as u64 }

struct Loaded {
    text: Vec<u8>,
    data: Vec<u8>,
    text_base: u64,
    data_base: u64,
}

fn load(obj: &[u8], isa: Isa, text_base: u64, data_base: u64) -> Loaded {
    load_r(obj, isa, text_base, data_base, &resolver)
}

fn load_r(obj: &[u8], isa: Isa, text_base: u64, data_base: u64, resolver: &dyn Fn(&[u8]) -> Option<u64>) -> Loaded {
    let m = Module::parse(obj, Some(isa)).expect("parse");
    let l = m.layout().expect("layout");
    let mut text = vec![0xa5u8; l.text_size as usize];
    let mut data = vec![0xa5u8; l.data_size as usize];
    m.load(&mut text, text_base, &mut data, data_base, &mut |n: &[u8]| resolver(n)).expect("load");
    Loaded { text, data, text_base, data_base }
}

/// Check every relocation of `obj` against the decoded result; returns the
/// per-type counts so a test can assert which kinds were covered.
fn check_all(obj: &[u8], isa: Isa, ld: &Loaded) -> BTreeMap<u32, usize> {
    check_all_r(obj, isa, ld, &resolver)
}

/// [`check_all`] with the caller's import resolver.
fn check_all_r(obj: &[u8], isa: Isa, ld: &Loaded, resolver: &dyn Fn(&[u8]) -> Option<u64>) -> BTreeMap<u32, usize> {
    let m = Module::parse(obj, Some(isa)).unwrap();
    let (shs, syms, rels) = read_elf(obj);
    let base = |r: Region| if r == Region::Text { ld.text_base } else { ld.data_base };
    let sym_addr = |i: usize| -> u64 {
        let s = &syms[i];
        match s.shndx {
            0 => resolver(s.name.as_bytes()).unwrap(),
            n => {
                let (r, at) = m.placement(n as usize).unwrap().expect("symbol in an unplaced section");
                base(r) + at + s.value
            }
        }
    };
    let mut counts = BTreeMap::new();
    for r in &rels {
        if shs[r.section].flags & 2 == 0 {
            continue; // not loaded
        }
        let (region, at) = m.placement(r.section).unwrap().unwrap();
        let buf = if region == Region::Text { &ld.text } else { &ld.data };
        let site = (at + r.off) as usize;
        let p = base(region) + at + r.off;
        let s = sym_addr(r.sym);
        let v = s.wrapping_add(r.addend as u64);
        let pc = v.wrapping_sub(p) as i64;
        let w = |o: usize| u32le(buf, site + o);
        match (isa, r.kind) {
            (Isa::Riscv64, 2) => assert_eq!(u64le(buf, site), v, "R_RISCV_64 at {:#x}", r.off),
            (Isa::Riscv64, 18 | 19) => {
                assert_eq!(w(0) & 0x7f, 0x17, "CALL: auipc expected at {:#x}", r.off);
                assert_eq!(rv_u_imm(w(0)) + rv_i_imm(w(4)), pc, "CALL at {:#x}", r.off);
            }
            (Isa::Riscv64, 23) => {
                // Checked through its LO12 partners below; here only the
                // opcode: the field must be on an auipc.
                assert_eq!(w(0) & 0x7f, 0x17, "PCREL_HI20 not on auipc at {:#x}", r.off);
            }
            (Isa::Riscv64, 24 | 25) => {
                // The label names the auipc: hi + lo must reach the HI20's
                // target from the auipc's own address.
                let label = syms[r.sym].value;
                let hi = rels.iter().find(|h| h.kind == 23 && h.section == r.section && h.off == label).expect("paired HI20");
                let p_hi = base(region) + at + label;
                let target = sym_addr(hi.sym).wrapping_add(hi.addend as u64);
                let hi_imm = rv_u_imm(u32le(buf, (at + label) as usize));
                let lo = if r.kind == 24 { rv_i_imm(w(0)) } else { rv_s_imm(w(0)) };
                assert_eq!((p_hi as i64 + hi_imm + lo) as u64, target, "PCREL_LO12 at {:#x}", r.off);
            }
            (Isa::Riscv64, 35) => {
                // ADD32/SUB32 pairs (label differences: switch tables, the
                // riscv64 `__ksymtab` has none but `.rodata` does): the field
                // ends as its object-file content + (S+A of ADD) - (S+A of SUB).
                let sub = rels.iter().find(|q| q.kind == 39 && q.section == r.section && q.off == r.off).expect("paired SUB32");
                let vsub = sym_addr(sub.sym).wrapping_add(sub.addend as u64);
                let orig = u32le(obj, shs[r.section].off + r.off as usize);
                assert_eq!(w(0), orig.wrapping_add(v as u32).wrapping_sub(vsub as u32), "ADD32/SUB32 at {:#x}", r.off);
            }
            (Isa::Riscv64, 39) => {
                assert!(rels.iter().any(|q| q.kind == 35 && q.section == r.section && q.off == r.off), "SUB32 without ADD32 at {:#x}", r.off);
            }
            (Isa::Aarch64, 261) => assert_eq!(w(0) as i32 as i64, pc, "PREL32 at {:#x}", r.off),
            (Isa::Aarch64, 257) => assert_eq!(u64le(buf, site), v, "ABS64 at {:#x}", r.off),
            (Isa::Aarch64, 282 | 283) => assert_eq!(a64_imm26(w(0)), pc, "CALL26 at {:#x}", r.off),
            (Isa::Aarch64, 275) => {
                let pages = ((v & !0xfff) as i64 - (p & !0xfff) as i64) >> 12;
                assert_eq!(a64_adr(w(0)), pages, "ADRP at {:#x}", r.off);
                assert_eq!(w(0) >> 31, 1, "ADRP opcode bit");
            }
            (Isa::Aarch64, 277) => assert_eq!(a64_imm12(w(0)), v & 0xfff, "ADD_LO12 at {:#x}", r.off),
            (Isa::Aarch64, 278 | 284 | 285 | 286 | 299) => {
                let shift = match r.kind { 278 => 0, 284 => 1, 285 => 2, 286 => 3, _ => 4 };
                assert_eq!(a64_imm12(w(0)) << shift, v & 0xfff, "LDST{} at {:#x}", 8 << shift, r.off);
            }
            (isa, k) => panic!("{isa:?} relocation type {k} in the fixture has no oracle: add one"),
        }
        *counts.entry(r.kind).or_insert(0) += 1;
    }
    counts
}

// ── encoders vs llvm-mc ─────────────────────────────────────────────────────

fn le32(b: [u8; 4]) -> u32 { u32::from_le_bytes(b) }
fn le16(b: [u8; 2]) -> u16 { u16::from_le_bytes(b) }

#[test]
fn riscv64_encoders_match_llvm_mc() {
    use encode::riscv64::*;
    // jal ra, 0 -> jal ra, 2048 ; j 0 -> j -1048576
    assert_eq!(j_type(le32([0xef, 0, 0, 0]), 2048), le32([0xef, 0x00, 0x10, 0x00]));
    assert_eq!(j_type(le32([0x6f, 0, 0, 0]), -1048576), le32([0x6f, 0x00, 0x00, 0x80]));
    // beq a0,a1,0 -> -4096 ; bne a0,a1,0 -> 4094
    assert_eq!(b_type(le32([0x63, 0x00, 0xb5, 0x00]), -4096), le32([0x63, 0x00, 0xb5, 0x80]));
    assert_eq!(b_type(le32([0x63, 0x10, 0xb5, 0x00]), 4094), le32([0xe3, 0x1f, 0xb5, 0x7e]));
    // c.beqz a0,0 -> 254 ; c.bnez a1,0 -> -256
    assert_eq!(cb_type(le16([0x01, 0xc1]), 254), le16([0x7d, 0xcd]));
    assert_eq!(cb_type(le16([0x81, 0xe1]), -256), le16([0x81, 0xf1]));
    // c.j 0 -> -2048 / 2046
    assert_eq!(cj_type(le16([0x01, 0xa0]), -2048), le16([0x01, 0xb0]));
    assert_eq!(cj_type(le16([0x01, 0xa0]), 2046), le16([0xfd, 0xaf]));
    // auipc ra,0 -> 0xfffff ; lui a0,0 -> 0x80000
    assert_eq!(u_type(le32([0x97, 0, 0, 0]), 0xfffff), le32([0x97, 0xf0, 0xff, 0xff]));
    assert_eq!(u_type(le32([0x37, 0x05, 0, 0]), 0x80000), le32([0x37, 0x05, 0x00, 0x80]));
    // jalr ra,0(ra) -> 2047 ; sd a0,0(sp) -> -8 ; sw a1,0(a2) -> 2047
    assert_eq!(i_type(le32([0xe7, 0x80, 0, 0]), 2047), le32([0xe7, 0x80, 0xf0, 0x7f]));
    assert_eq!(s_type(le32([0x23, 0x30, 0xa1, 0x00]), -8), le32([0x23, 0x3c, 0xa1, 0xfe]));
    assert_eq!(s_type(le32([0x23, 0x20, 0xb6, 0x00]), 2047), le32([0xa3, 0x2f, 0xb6, 0x7e]));
    // The %hi/%lo split rounds so the sign-extended low part adds back.
    for v in [0i64, 1, 0x7ff, 0x800, 0xfff, -1, -0x800, -0x801, 0x7fff_f7ff, -0x8000_0000] {
        let (hi, lo) = hi_lo(v);
        assert!((-0x800..0x800).contains(&lo), "{v:#x}");
        assert_eq!((hi << 12) + lo, v);
    }
}

#[test]
fn aarch64_encoders_match_llvm_mc() {
    use encode::aarch64::*;
    let adrp0 = le32([0x00, 0x00, 0x00, 0x90]);
    assert_eq!(adr(adrp0, 0x12345000 >> 12), le32([0x20, 0x1a, 0x09, 0xb0]));
    assert_eq!(adr(le32([0x03, 0x00, 0x00, 0x90]), -1), le32([0xe3, 0xff, 0xff, 0xf0]));
    assert_eq!(adr(le32([0x00, 0x00, 0x00, 0x10]), 0xfffff), le32([0xe0, 0xff, 0x7f, 0x70]));
    assert_eq!(imm12(le32([0x00, 0x00, 0x00, 0x91]), 0xabc), le32([0x00, 0xf0, 0x2a, 0x91]));
    assert_eq!(imm12(le32([0x20, 0x00, 0x40, 0xf9]), 4088 >> 3), le32([0x20, 0xfc, 0x47, 0xf9]));
    assert_eq!(imm12(le32([0x62, 0x00, 0x40, 0xb9]), 4092 >> 2), le32([0x62, 0xfc, 0x4f, 0xb9]));
    assert_eq!(imm12(le32([0x20, 0x00, 0xc0, 0x3d]), 32 >> 4), le32([0x20, 0x08, 0xc0, 0x3d]));
    assert_eq!(imm26(le32([0, 0, 0, 0x94]), 134217724), le32([0xff, 0xff, 0xff, 0x95]));
    assert_eq!(imm26(le32([0, 0, 0, 0x14]), -134217728), le32([0x00, 0x00, 0x00, 0x16]));
    assert_eq!(imm19(le32([0, 0, 0, 0x54]), -1048576), le32([0x00, 0x00, 0x80, 0x54]));
    assert_eq!(imm19(le32([0x00, 0x00, 0x00, 0xb4]), 262140), le32([0xe0, 0xff, 0x1f, 0xb4]));
    assert_eq!(imm14(le32([0x00, 0x00, 0x28, 0x36]), -32768), le32([0x00, 0x00, 0x2c, 0x36]));
    assert_eq!(imm16(le32([0x00, 0x00, 0xa0, 0xd2]), 0x1234), le32([0x80, 0x46, 0xa2, 0xd2]));
    assert_eq!(imm16(le32([0x00, 0x00, 0xe0, 0xf2]), 0xbeef), le32([0xe0, 0xdd, 0xf7, 0xf2]));
}

// ── whole modules ───────────────────────────────────────────────────────────

#[test]
fn riscv64_module_every_relocation_checks() {
    let obj = ko(Isa::Riscv64);
    let ld = load(&obj, Isa::Riscv64, 0x1100_0000, 0x1110_0000);
    let c = check_all(&obj, Isa::Riscv64, &ld);
    // The kinds a medany module carries, all present in the fixture.
    for k in [2u32, 19, 23, 24, 25] {
        assert!(c.get(&k).copied().unwrap_or(0) > 0, "fixture lost relocation type {k}: {c:?}");
    }
}

#[test]
fn aarch64_module_every_relocation_checks() {
    let obj = ko(Isa::Aarch64);
    let ld = load(&obj, Isa::Aarch64, 0x1100_0000, 0x1110_0000);
    let c = check_all(&obj, Isa::Aarch64, &ld);
    for k in [257u32, 275, 277, 283, 285, 286] {
        assert!(c.get(&k).copied().unwrap_or(0) > 0, "fixture lost relocation type {k}: {c:?}");
    }
}

/// Same module at other bases (page offsets that make ADRP/AUIPC carry, and
/// a data region BELOW the text), all within BL reach (+-128 MiB) of the
/// imports at 0x1000_2000/0x1000_3000: the oracle must still agree everywhere.
#[test]
fn modules_relocate_at_awkward_bases() {
    for isa in [Isa::Riscv64, Isa::Aarch64] {
        let obj = ko(isa);
        for (t, d) in [(0x1000_0ff0u64 & !0xf, 0x0fff_f000u64), (0x17ff_f000, 0x1000_4000), (0x1000_5000, 0x1000_5ff0 & !0xf)] {
            let ld = load(&obj, isa, t, d);
            check_all(&obj, isa, &ld);
        }
    }
}

#[test]
fn text_region_holds_only_code_and_data_never_code() {
    for isa in [Isa::Riscv64, Isa::Aarch64] {
        let obj = ko(isa);
        let m = Module::parse(&obj, Some(isa)).unwrap();
        let (shs, _, _) = read_elf(&obj);
        let mut text = 0;
        for (i, s) in shs.iter().enumerate() {
            match m.placement(i).unwrap() {
                Some((Region::Text, _)) => {
                    assert!(s.flags & 4 != 0, "{} placed in text without SHF_EXECINSTR", s.name);
                    text += 1;
                }
                Some((Region::Data, _)) => assert!(s.flags & 4 == 0, "{} is code placed in data", s.name),
                None => assert!(s.flags & 2 == 0 || s.name == ".modinfo", "{} allocated but not placed", s.name),
            }
        }
        assert!(text >= 1);
        let names: Vec<_> = shs.iter().enumerate().filter(|(i, _)| m.placement(*i).unwrap() == None).map(|(_, s)| s.name.clone()).collect();
        assert!(names.contains(&".modinfo".to_string()));
        let l = m.layout().unwrap();
        assert!(l.text_size > 0 && l.data_size > 0);
    }
}

#[test]
fn imports_are_counted_and_exports_found() {
    for isa in [Isa::Riscv64, Isa::Aarch64] {
        let obj = ko(isa);
        let m = Module::parse(&obj, Some(isa)).unwrap();
        let mut names = Vec::new();
        let n = m.for_each_import(|s| names.push(s.to_vec())).unwrap();
        names.sort();
        assert_eq!(n, 2);
        assert_eq!(names, vec![b"lx_test_log".to_vec(), b"lx_test_mix".to_vec()]);
        let mut t = vec![0; m.layout().unwrap().text_size as usize];
        let mut d = vec![0; m.layout().unwrap().data_size as usize];
        let l = m.load(&mut t, 0x1400_0000, &mut d, 0x1410_0000, &mut resolver).unwrap();
        let init = l.symbol(b"lxtest_init").expect("init exported");
        assert!((0x1400_0000..0x1400_0000 + t.len() as u64).contains(&init));
        assert!(l.symbol(b"step").is_none(), "a static function is not an export");
        assert!(l.symbol(b"lxtest_scratch").is_some());
    }
}

// ── refusals ────────────────────────────────────────────────────────────────

#[test]
fn modinfo_admission() {
    for isa in [Isa::Riscv64, Isa::Aarch64] {
        let obj = ko(isa);
        let m = Module::parse(&obj, Some(isa)).unwrap();
        assert_eq!(m.modinfo(b"license"), Some(&b"Dual Apache/GPL"[..]));
        assert_eq!(m.modinfo(b"name"), Some(&b"lxtest"[..]));
        assert_eq!(admit(&m, b"azos-lx0"), Ok(()));
        assert_eq!(admit(&m, b"azos-lx1"), Err(Error::Vermagic(b"azos-lx0")));
        // Canary: the same bytes with the licence tag rewritten in place.
        let mut bad = obj.clone();
        let at = bad.windows(15).position(|w| w == b"Dual Apache/GPL").unwrap();
        bad[at..at + 15].copy_from_slice(b"Proprietary\0\0\0\0");
        let mb = Module::parse(&bad, Some(isa)).unwrap();
        assert_eq!(admit(&mb, b"azos-lx0"), Err(Error::License(b"Proprietary")));
    }
    assert!(license_is_gpl_compatible(b"GPL v2"));
    assert!(!license_is_gpl_compatible(b"GPL v3"), "exact match only, like Linux");
    assert!(!license_is_gpl_compatible(b"Proprietary"));
}

#[test]
fn unresolved_import_is_refused_before_any_relocation() {
    let obj = ko(Isa::Riscv64);
    let m = Module::parse(&obj, None).unwrap();
    let l = m.layout().unwrap();
    let mut t = vec![0; l.text_size as usize];
    let mut d = vec![0; l.data_size as usize];
    let mut only_log = |n: &[u8]| if n == b"lx_test_log" { Some(LOG) } else { None };
    assert_eq!(m.load(&mut t, 0x1000, &mut d, 0x10_0000, &mut only_log).unwrap_err(), Error::Unresolved(b"lx_test_mix"));
}

#[test]
fn wrong_isa_and_garbage_are_refused() {
    let rv = ko(Isa::Riscv64);
    assert!(matches!(Module::parse(&rv, Some(Isa::Aarch64)), Err(Error::WrongMachine(243))));
    assert_eq!(Module::parse(b"not an elf", None).unwrap_err(), Error::NotElf64Le);
    let mut exec = rv.clone();
    exec[16] = 2; // ET_EXEC
    assert_eq!(Module::parse(&exec, None).unwrap_err(), Error::NotRelocatable);
    // Every truncation of a real module is refused or loads, and never
    // panics: the loader runs on bytes a compromised volume could supply
    // (before the kernel's digest check would refuse them anyway).
    for isa in [Isa::Riscv64, Isa::Aarch64] {
        let obj = ko(isa);
        for n in 0..obj.len() {
            let _ = Module::parse(&obj[..n], None).and_then(|m| m.layout().map(|_| ()));
        }
        // Single-byte corruptions of the header and section table.
        let shoff = u64le(&obj, 40) as usize;
        for at in (0..64).chain(shoff..obj.len()) {
            let mut b = obj.clone();
            b[at] ^= 0xff;
            if let Ok(m) = Module::parse(&b, None) {
                if let Ok(l) = m.layout() {
                    if l.text_size < 1 << 20 && l.data_size < 1 << 20 {
                        let mut t = vec![0; l.text_size as usize];
                        let mut d = vec![0; l.data_size as usize];
                        let _ = m.load(&mut t, 0x1000_0000, &mut d, 0x1100_0000, &mut resolver);
                    }
                }
            }
        }
    }
}

#[test]
fn out_of_reach_branch_is_refused_not_truncated() {
    // riscv64: an import 3 GiB away is beyond auipc+jalr (+-2 GiB).
    let obj = ko(Isa::Riscv64);
    let m = Module::parse(&obj, None).unwrap();
    let l = m.layout().unwrap();
    let mut t = vec![0; l.text_size as usize];
    let mut d = vec![0; l.data_size as usize];
    let mut far = |n: &[u8]| resolver(n).map(|a| a + (3u64 << 30));
    assert!(matches!(m.load(&mut t, 0x1000_0000, &mut d, 0x1010_0000, &mut far), Err(Error::Overflow(19, _))));
    // aarch64: 200 MiB is beyond BL's +-128 MiB.
    let obj = ko(Isa::Aarch64);
    let m = Module::parse(&obj, None).unwrap();
    let l = m.layout().unwrap();
    let mut t = vec![0; l.text_size as usize];
    let mut d = vec![0; l.data_size as usize];
    let mut far = |n: &[u8]| resolver(n).map(|a| a + (200u64 << 20));
    assert!(matches!(m.load(&mut t, 0x1000_0000, &mut d, 0x1010_0000, &mut far), Err(Error::Overflow(283, _))));
}

#[test]
fn small_or_misaligned_regions_are_refused() {
    let obj = ko(Isa::Aarch64);
    let m = Module::parse(&obj, None).unwrap();
    let l = m.layout().unwrap();
    let mut t = vec![0; l.text_size as usize - 1];
    let mut d = vec![0; l.data_size as usize];
    assert_eq!(m.load(&mut t, 0x1000, &mut d, 0x2000, &mut resolver).unwrap_err(), Error::RegionTooSmall);
    let mut t = vec![0; l.text_size as usize];
    assert_eq!(m.load(&mut t, 0x1001, &mut d, 0x2000, &mut resolver).unwrap_err(), Error::RegionTooSmall);
}

/// Canary for the oracle itself: flip one immediate bit in a relocated
/// call and `check_all` must notice. If this ever passes, the whole-module
/// tests above prove nothing.
#[test]
fn oracle_canary_detects_a_wrong_relocation() {
    for isa in [Isa::Riscv64, Isa::Aarch64] {
        let obj = ko(isa);
        let mut ld = load(&obj, isa, 0x1100_0000, 0x1110_0000);
        let (shs, _, rels) = read_elf(&obj);
        let call = rels.iter().find(|r| matches!(r.kind, 19 | 283) && shs[r.section].flags & 4 != 0).unwrap();
        let m = Module::parse(&obj, None).unwrap();
        let (_, at) = m.placement(call.section).unwrap().unwrap();
        let site = (at + call.off) as usize;
        // Bit 21 of the auipc (riscv64) or bit 3 of BL's imm26 (aarch64).
        let bit = if isa == Isa::Riscv64 { 1u32 << 21 } else { 1 << 3 };
        let w = u32le(&ld.text, site) ^ bit;
        ld.text[site..site + 4].copy_from_slice(&w.to_le_bytes());
        let r = std::panic::catch_unwind(|| check_all(&obj, isa, &ld));
        assert!(r.is_err(), "{isa:?}: the oracle accepted a corrupted call");
    }
}

// ── Linux modules built by Kbuild (RFC-0053 L1) ─────────────────────────────
//
// `make lx-kbuild` builds `build/lx/kbuild/<isa>/{lxbase,xz_dec}.ko` with
// Linux's own Kbuild in the pinned container. Without podman those files do
// not exist and these tests print SKIP and pass: the gate's Kbuild row is
// where a missing build is reported.

fn kbuild(isa: Isa, name: &str) -> Option<Vec<u8>> {
    let dir = match isa {
        Isa::Riscv64 => "riscv64",
        Isa::Aarch64 => "aarch64",
    };
    let path = format!("{}/../../../build/lx/kbuild/{dir}/{name}", env!("CARGO_MANIFEST_DIR"));
    match std::fs::read(&path) {
        Ok(b) => Some(b),
        Err(_) => {
            eprintln!("SKIP: {path} not built (make lx-kbuild)");
            None
        }
    }
}

/// The host ABI (`lx/HOST_ABI`) at fixed addresses near the text.
fn host_abi(name: &[u8]) -> Option<u64> {
    let abi = std::fs::read_to_string(format!("{}/../../../lx/HOST_ABI", env!("CARGO_MANIFEST_DIR"))).unwrap();
    abi.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .position(|l| l.trim().as_bytes() == name)
        .map(|i| 0x1000_2000 + 0x100 * i as u64)
}

const BASE_T: u64 = 0x1100_0000;
const BASE_D: u64 = 0x1180_0000;
const XZ_T: u64 = 0x1200_0000;
const XZ_D: u64 = 0x1280_0000;

/// Loads lxbase.ko against the host ABI and xz_dec.ko against lxbase's
/// `__ksymtab` + the host ABI (the order lxsrv uses), checking every
/// relocation of both with the oracle.
fn kbuild_chain(isa: Isa) -> Option<(Vec<u8>, Loaded, Vec<u8>, Loaded)> {
    let base = kbuild(isa, "lxbase.ko")?;
    let xz = kbuild(isa, "xz_dec.ko")?;
    let lb = load_r(&base, isa, BASE_T, BASE_D, &host_abi);
    let cb = check_all_r(&base, isa, &lb, &host_abi);
    let bm = Module::parse(&base, Some(isa)).unwrap();
    let mut t = lb.text.clone();
    let mut d = lb.data.clone();
    let bl = bm.load(&mut t, BASE_T, &mut d, BASE_D, &mut |n: &[u8]| host_abi(n)).unwrap();
    let chain = |n: &[u8]| bl.export(&d, n).or_else(|| host_abi(n));
    let lx = load_r(&xz, isa, XZ_T, XZ_D, &chain);
    let cx = check_all_r(&xz, isa, &lx, &chain);
    let want: &[u32] = match isa {
        Isa::Riscv64 => &[2, 19, 23, 24, 35, 39],
        Isa::Aarch64 => &[261, 275, 277, 283],
    };
    for k in want {
        let n = cb.get(k).copied().unwrap_or(0) + cx.get(k).copied().unwrap_or(0);
        assert!(n > 0, "{isa:?}: Kbuild modules lost relocation type {k}: {cb:?} {cx:?}");
    }
    Some((base, lb, xz, lx))
}

#[test]
fn kbuild_modules_every_relocation_checks() {
    for isa in [Isa::Riscv64, Isa::Aarch64] {
        let _ = kbuild_chain(isa);
    }
}

#[test]
fn kbuild_exports_come_from_the_ksymtab_only() {
    for isa in [Isa::Riscv64, Isa::Aarch64] {
        let Some((base, lb, xz, lx)) = kbuild_chain(isa) else { continue };
        let bm = Module::parse(&base, Some(isa)).unwrap();
        let mut t = lb.text.clone();
        let mut d = lb.data.clone();
        let bl = bm.load(&mut t, BASE_T, &mut d, BASE_D, &mut |n: &[u8]| host_abi(n)).unwrap();
        let mut names = Vec::new();
        let n = bl.for_each_export(&d, |s, _| names.push(String::from_utf8_lossy(s).into_owned())).unwrap();
        names.sort();
        assert_eq!(n, 9, "{isa:?}: {names:?}");
        for s in ["__kmalloc_cache_noprof", "crc32_le", "kfree", "kmalloc_caches", "vfree"] {
            assert_eq!(bl.export(&d, s.as_bytes()), bl.symbol(s.as_bytes()), "{isa:?} {s}");
            assert!(bl.export(&d, s.as_bytes()).is_some());
        }
        assert_eq!(bl.export(&d, b"lx_kmalloc"), None, "a static helper is not exported");

        let xm = Module::parse(&xz, Some(isa)).unwrap();
        let chain = |n: &[u8]| bl.export(&d, n).or_else(|| host_abi(n));
        let mut t2 = lx.text.clone();
        let mut d2 = lx.data.clone();
        let xl = xm.load(&mut t2, XZ_T, &mut d2, XZ_D, &mut |n: &[u8]| chain(n)).unwrap();
        assert_eq!(xl.for_each_export(&d2, |_, _| {}), Some(4));
        let run = xl.export(&d2, b"xz_dec_run").expect("xz_dec_run exported");
        assert_eq!(Some(run), xl.symbol(b"xz_dec_run"));
        assert!((XZ_T..XZ_T + t2.len() as u64).contains(&run));
        // A global the module does not export: the symtab has it, the
        // ksymtab does not, and only the ksymtab links modules.
        assert!(xl.symbol(b"xz_dec_lzma2_run").is_some());
        assert_eq!(xl.export(&d2, b"xz_dec_lzma2_run"), None);
    }
}

#[test]
fn kbuild_modinfo_and_notes() {
    let pin = std::fs::read_to_string(format!("{}/../../../lx/LINUX_PIN", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let tag = pin.lines().find_map(|l| l.strip_prefix("tag=v")).unwrap().to_string();
    for isa in [Isa::Riscv64, Isa::Aarch64] {
        let arch = if isa == Isa::Riscv64 { "riscv" } else { "aarch64" };
        let vermagic = format!("{tag} SMP preempt {arch}");
        for (name, license) in [("lxbase.ko", &b"GPL"[..]), ("xz_dec.ko", &b"Dual BSD/GPL"[..])] {
            let Some(obj) = kbuild(isa, name) else { continue };
            let m = Module::parse(&obj, Some(isa)).unwrap();
            assert_eq!(m.modinfo(b"license"), Some(license), "{isa:?} {name}");
            assert_eq!(admit(&m, vermagic.as_bytes()), Ok(()), "{isa:?} {name}: vermagic {:?}",
                       m.modinfo(b"vermagic").map(|v| String::from_utf8_lossy(v).into_owned()));
            assert!(admit(&m, b"7.2.8 SMP preempt riscv").is_err());
            let (shs, _, _) = read_elf(&obj);
            for (i, s) in shs.iter().enumerate() {
                if s.name.starts_with(".note") {
                    assert_eq!(m.placement(i).unwrap(), None, "{name}: {} placed", s.name);
                }
            }
        }
    }
}

/// The loader classifies sections once at parse time (`placement` used to
/// re-walk every section per relocation). Its answer must equal an
/// independent walk over this file's own ELF reader for every section of
/// every module we have: the L0b fixtures and the Kbuild set.
#[test]
fn placement_equals_an_independent_walk() {
    let mut objs = vec![(Isa::Riscv64, ko(Isa::Riscv64)), (Isa::Aarch64, ko(Isa::Aarch64))];
    for isa in [Isa::Riscv64, Isa::Aarch64] {
        for n in ["lxbase.ko", "xz_dec.ko"] {
            if let Some(o) = kbuild(isa, n) {
                objs.push((isa, o));
            }
        }
    }
    for (isa, obj) in objs {
        let m = Module::parse(&obj, Some(isa)).unwrap();
        let (shs, _, _) = read_elf(&obj);
        let b = &obj;
        let shoff = u64le(b, 40) as usize;
        let (mut text, mut data) = (0u64, 0u64);
        for (i, s) in shs.iter().enumerate() {
            let align = u64le(b, shoff + i * 64 + 48).max(1);
            let placed = i != 0 && s.flags & 2 != 0 && s.kind != 7 && s.name != ".modinfo" && s.name != "__versions";
            let want = if placed {
                let cur = if s.flags & 4 != 0 { &mut text } else { &mut data };
                let at = (*cur + align - 1) & !(align - 1);
                *cur = at + s.size as u64;
                Some((if s.flags & 4 != 0 { Region::Text } else { Region::Data }, at))
            } else {
                None
            };
            assert_eq!(m.placement(i).unwrap(), want, "{isa:?} section {} ({})", i, s.name);
        }
    }
}
