// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The relocation walk against ELF files: a synthetic one built here, and the
//! real kernel when `AZOS_KASLR_ELF` names one.
//!
//! The boot never parses an ELF (`boot.S` hands the relocation table's bounds
//! to Rust as two addresses); this minimal reader exists so the walk can be
//! run on the bytes the linker produced, the way `llvm-objcopy -O binary`
//! lays them out (by physical address), and so a synthetic image has the same
//! shape: loaded segments, a `.rela.dyn` section, a link address that differs
//! from the load address.

use azos_arch_api::kaslr::*;

const PT_LOAD: u32 = 1;
const SHT_RELA: u32 = 4;

fn u16le(b: &[u8], at: usize) -> u64 { u16::from_le_bytes(b[at..at + 2].try_into().unwrap()) as u64 }
fn u32le(b: &[u8], at: usize) -> u64 { u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as u64 }
fn u64le(b: &[u8], at: usize) -> u64 { u64::from_le_bytes(b[at..at + 8].try_into().unwrap()) }

/// A flattened image: the loaded segments laid out by physical address.
pub struct Flat {
    /// Bytes from the lowest load address to the end of the last segment.
    pub bytes: Vec<u8>,
    /// Link (virtual) address of `bytes[0]`.
    pub link_start: u64,
    /// `.rela.dyn`: (offset in `bytes`, size).
    pub rela: (usize, usize),
}

/// Parse an ELF64 little-endian file.
pub fn flatten(elf: &[u8]) -> Flat {
    assert_eq!(&elf[0..4], b"\x7fELF");
    assert_eq!(elf[4], 2, "ELF64");
    let (phoff, shoff) = (u64le(elf, 32) as usize, u64le(elf, 40) as usize);
    let (phentsize, phnum) = (u16le(elf, 54) as usize, u16le(elf, 56) as usize);
    let (shentsize, shnum, shstrndx) = (u16le(elf, 58) as usize, u16le(elf, 60) as usize, u16le(elf, 62) as usize);

    let mut segs = Vec::new();
    for i in 0..phnum {
        let p = phoff + i * phentsize;
        if u32le(elf, p) as u32 == PT_LOAD {
            let (off, vaddr, paddr, filesz, memsz) =
                (u64le(elf, p + 8), u64le(elf, p + 16), u64le(elf, p + 24), u64le(elf, p + 32), u64le(elf, p + 40));
            segs.push((off as usize, vaddr, paddr, filesz as usize, memsz));
        }
    }
    let lo = segs.iter().map(|s| s.2).min().expect("a PT_LOAD");
    let hi = segs.iter().map(|s| s.2 + s.4).max().unwrap();
    let mut bytes = vec![0u8; (hi - lo) as usize];
    for &(off, _, paddr, filesz, _) in &segs {
        let at = (paddr - lo) as usize;
        bytes[at..at + filesz].copy_from_slice(&elf[off..off + filesz]);
    }
    // The link address of the lowest-loaded byte: its segment's vaddr.
    let link_start = segs.iter().find(|s| s.2 == lo).map(|s| s.1).unwrap();

    let sh = |i: usize| shoff + i * shentsize;
    let strtab_off = u64le(elf, sh(shstrndx) + 24) as usize;
    let mut rela = None;
    for i in 0..shnum {
        let name_off = u32le(elf, sh(i)) as usize;
        let name_start = strtab_off + name_off;
        let name_end = name_start + elf[name_start..].iter().position(|&c| c == 0).unwrap();
        if &elf[name_start..name_end] == b".rela.dyn" {
            assert_eq!(u32le(elf, sh(i) + 4) as u32, SHT_RELA);
            let (addr, size) = (u64le(elf, sh(i) + 16), u64le(elf, sh(i) + 32) as usize);
            // The section is in a loaded segment: its place in `bytes` follows its link address.
            rela = Some(((addr - link_start) as usize, size));
        }
    }
    Flat { bytes, link_start, rela: rela.expect("a .rela.dyn section") }
}

/// The value of symbol `name` in the ELF's `.symtab`, if it has one.
pub fn symbol(elf: &[u8], name: &str) -> Option<u64> {
    let shoff = u64le(elf, 40) as usize;
    let (shentsize, shnum) = (u16le(elf, 58) as usize, u16le(elf, 60) as usize);
    let sh = |i: usize| shoff + i * shentsize;
    for i in 0..shnum {
        if u32le(elf, sh(i) + 4) as u32 != 2 {
            continue; // SHT_SYMTAB
        }
        let (off, size, link) = (u64le(elf, sh(i) + 24) as usize, u64le(elf, sh(i) + 32) as usize, u32le(elf, sh(i) + 40) as usize);
        let strtab = u64le(elf, sh(link) + 24) as usize;
        for k in 0..size / 24 {
            let e = off + k * 24;
            let n = strtab + u32le(elf, e) as usize;
            let end = n + elf[n..].iter().position(|&c| c == 0)?;
            if &elf[n..end] == name.as_bytes() {
                return Some(u64le(elf, e + 8));
            }
        }
    }
    None
}

/// Build a small ELF64 with one PT_LOAD at `vaddr` loaded at `paddr`, holding
/// `body` (the image bytes, first at `vaddr`), and a `.rela.dyn` section over
/// the bytes `[rela_at, rela_at + rela_len)` of the body.
pub fn synthetic_elf(vaddr: u64, paddr: u64, body: &[u8], rela_at: usize, rela_len: usize) -> Vec<u8> {
    let shstr = b"\0.rela.dyn\0.shstrtab\0";
    let file_body_off = 0x1000usize;
    let shstr_off = file_body_off + body.len();
    let sh_off = (shstr_off + shstr.len() + 7) & !7;
    let mut f = vec![0u8; sh_off + 3 * 64];
    f[0..4].copy_from_slice(b"\x7fELF");
    f[4] = 2; // ELF64
    f[5] = 1; // little endian
    f[6] = 1;
    f[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
    f[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
    f[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    f[40..48].copy_from_slice(&(sh_off as u64).to_le_bytes()); // e_shoff
    f[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    f[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    f[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
    f[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    f[60..62].copy_from_slice(&3u16.to_le_bytes()); // e_shnum
    f[62..64].copy_from_slice(&2u16.to_le_bytes()); // e_shstrndx
    // PT_LOAD
    let p = 64;
    f[p..p + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
    f[p + 4..p + 8].copy_from_slice(&5u32.to_le_bytes());
    f[p + 8..p + 16].copy_from_slice(&(file_body_off as u64).to_le_bytes());
    f[p + 16..p + 24].copy_from_slice(&vaddr.to_le_bytes());
    f[p + 24..p + 32].copy_from_slice(&paddr.to_le_bytes());
    f[p + 32..p + 40].copy_from_slice(&(body.len() as u64).to_le_bytes());
    f[p + 40..p + 48].copy_from_slice(&(body.len() as u64).to_le_bytes());
    f[file_body_off..file_body_off + body.len()].copy_from_slice(body);
    f[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);
    // Section 1: .rela.dyn (name at 1); section 2: .shstrtab (name at 11).
    let s1 = sh_off + 64;
    f[s1..s1 + 4].copy_from_slice(&1u32.to_le_bytes());
    f[s1 + 4..s1 + 8].copy_from_slice(&SHT_RELA.to_le_bytes());
    f[s1 + 16..s1 + 24].copy_from_slice(&(vaddr + rela_at as u64).to_le_bytes());
    f[s1 + 24..s1 + 32].copy_from_slice(&((file_body_off + rela_at) as u64).to_le_bytes());
    f[s1 + 32..s1 + 40].copy_from_slice(&(rela_len as u64).to_le_bytes());
    let s2 = sh_off + 128;
    f[s2..s2 + 4].copy_from_slice(&11u32.to_le_bytes());
    f[s2 + 4..s2 + 8].copy_from_slice(&3u32.to_le_bytes());
    f[s2 + 24..s2 + 32].copy_from_slice(&(shstr_off as u64).to_le_bytes());
    f[s2 + 32..s2 + 40].copy_from_slice(&(shstr.len() as u64).to_le_bytes());
    f
}

/// Run the walk over a flattened image at `delta`; return the number applied.
fn relocate(flat: &mut Flat, delta: u64, ty: u32) -> Result<usize, RelocError> {
    let (at, size) = flat.rela;
    // The table is read from a copy: the walk writes the image, and the
    // table lives in it.
    let table = flat.bytes[at..at + size].to_vec();
    let len = flat.bytes.len() as u64;
    unsafe { apply_relative(table.as_ptr(), table.len(), flat.bytes.as_mut_ptr(), len, flat.link_start, delta, ty) }
}

fn word(b: &[u8], at: usize) -> u64 { u64le(b, at) }

/// A synthetic image shaped like the kernel: code, a table of pointers into
/// the image, a RELA table, and a zero tail (bss/stack).
fn kernel_shaped() -> (Vec<u8>, u64, u64, Vec<(usize, u64)>) {
    const LINK: u64 = 0xFFFF_FF80_4008_0000;
    const PHYS: u64 = 0x4008_0000;
    let mut body = vec![0u8; 0x400];
    // Pointer words at 0x100.., addends inside the image (0x000..0x400).
    let slots: Vec<(usize, u64)> = vec![(0x100, LINK + 0x10), (0x108, LINK + 0x3F8), (0x110, LINK + 0x200), (0x1F8, LINK)];
    let rela_at = 0x300;
    for (i, &(off, addend)) in slots.iter().enumerate() {
        let e = rela_at + i * RELA_BYTES;
        body[e..e + 8].copy_from_slice(&(LINK + off as u64).to_le_bytes());
        body[e + 8..e + 16].copy_from_slice(&(R_AARCH64_RELATIVE as u64).to_le_bytes());
        body[e + 16..e + 24].copy_from_slice(&addend.to_le_bytes());
    }
    let elf = synthetic_elf(LINK, PHYS, &body, rela_at, slots.len() * RELA_BYTES);
    (elf, LINK, PHYS, slots)
}

#[test]
fn the_reader_lays_the_image_out_by_load_address_and_finds_the_table() {
    let (elf, link, _phys, slots) = kernel_shaped();
    let flat = flatten(&elf);
    assert_eq!(flat.link_start, link);
    assert_eq!(flat.bytes.len(), 0x400);
    assert_eq!(flat.rela, (0x300, slots.len() * RELA_BYTES));
}

#[test]
fn a_synthetic_elf_relocates_to_a_slid_base() {
    let (elf, link, phys, slots) = kernel_shaped();
    let mut flat = flatten(&elf);
    // Slide to 0xFFFF_FFC0_1234_0000 + the 512 KiB phase of the load address.
    let image_va = 0xFFFF_FFC0_1234_0000u64 + (phys & 0x1F_FFFF);
    let delta = image_va.wrapping_sub(link);
    assert_eq!(relocate(&mut flat, delta, R_AARCH64_RELATIVE), Ok(slots.len()));
    for &(off, addend) in &slots {
        let w = word(&flat.bytes, off);
        assert_eq!(w, addend.wrapping_add(delta), "word at {off:#x}");
        // The property that makes the image run: the pointer lands in the SLID image.
        assert!(w >= image_va && w < image_va + flat.bytes.len() as u64, "{w:#x} is inside the slid image");
    }
}

#[test]
fn a_synthetic_elf_at_delta_zero_gets_its_link_time_values() {
    let (elf, link, _phys, slots) = kernel_shaped();
    let mut flat = flatten(&elf);
    assert_eq!(flat.bytes[0x100..0x108], [0u8; 8], "the linker left the target zero");
    relocate(&mut flat, 0, R_AARCH64_RELATIVE).unwrap();
    for &(off, addend) in &slots {
        assert_eq!(word(&flat.bytes, off), addend);
    }
    assert!(link > 0);
}

#[test]
fn the_walk_rejects_another_isas_relocation_type() {
    let (elf, _link, _phys, _slots) = kernel_shaped();
    let mut flat = flatten(&elf);
    assert_eq!(
        relocate(&mut flat, 1, R_X86_64_RELATIVE),
        Err(RelocError::UnsupportedType { index: 0, ty: R_AARCH64_RELATIVE }),
    );
}

/// The real kernel, when the gate (or a developer) names it:
/// `AZOS_KASLR_ELF=<elf> AZOS_KASLR_ISA=<aarch64|riscv64|x86_64>` (default
/// aarch64), e.g. an image `tools/image/kaslr_image.sh <isa> slid` built.
/// A position-independent kernel link must hold nothing but the ISA's
/// `R_*_RELATIVE`, every entry inside the image, and every relocated pointer
/// must land inside the slid image. Skipped (and says so) when unset; fails
/// when the ELF is not a position-independent link (no `.rela.dyn`).
#[test]
fn the_real_kernel_relocates_cleanly_at_several_bases() {
    let Ok(path) = std::env::var("AZOS_KASLR_ELF") else {
        eprintln!("AZOS_KASLR_ELF not set: the real-kernel check is skipped");
        return;
    };
    let isa = std::env::var("AZOS_KASLR_ISA").unwrap_or_else(|_| "aarch64".into());
    let elf = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let flat = flatten(&elf);
    let n = flat.rela.1 / RELA_BYTES;
    assert!(n > 1000, "a kernel has thousands of pointer words, found {n}");
    // The image runs to `_kernel_end` (the boot stack lies beyond the last
    // loaded byte): a pointer to a symbol there is inside the image.
    let len = match symbol(&elf, "_kernel_end") {
        Some(end) => end - flat.link_start,
        None => flat.bytes.len() as u64,
    }
    .max(flat.bytes.len() as u64);
    // The relocation type, and slid bases inside the ISA's window with the
    // image's own phase below 2 MiB (what `pick_slide` preserves).
    let phase = flat.link_start & 0x1F_FFFF;
    let (ty, bases): (u32, [u64; 3]) = match isa.as_str() {
        "aarch64" => (R_AARCH64_RELATIVE, [flat.link_start, 0xFFFF_FFC0_0008_0000, 0xFFFF_FFDF_FF88_0000]),
        "riscv64" => (R_RISCV_RELATIVE, [flat.link_start, 0xFFFF_FFC0_0000_0000 + phase, 0xFFFF_FFFF_C000_0000 - 0x4000_0000 + phase]),
        "x86_64" => (R_X86_64_RELATIVE, [flat.link_start, 0xFFFF_FFFF_8000_0000 + phase + 0x20_0000, 0xFFFF_FFFF_8000_0000 + phase + 0x3000_0000]),
        other => panic!("AZOS_KASLR_ISA={other}: want aarch64, riscv64 or x86_64"),
    };
    for image_va in bases {
        let mut f = Flat { bytes: flat.bytes.clone(), link_start: flat.link_start, rela: flat.rela };
        let delta = image_va.wrapping_sub(flat.link_start);
        assert_eq!(relocate(&mut f, delta, ty), Ok(n), "base {image_va:#x}");
        let table = flat.bytes[flat.rela.0..flat.rela.0 + flat.rela.1].to_vec();
        for i in 0..n {
            let off = u64le(&table, i * RELA_BYTES) - flat.link_start;
            let addend = u64le(&table, i * RELA_BYTES + 16);
            let w = word(&f.bytes, off as usize);
            assert_eq!(w, addend.wrapping_add(delta), "entry {i} at {off:#x}");
            assert!(
                w >= image_va && w <= image_va + len,
                "entry {i}: {w:#x} leaves the image slid to {image_va:#x}..+{len:#x} (link addend {addend:#x})"
            );
        }
    }
}
