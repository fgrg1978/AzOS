// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Booting a guest kernel: the ELF into guest RAM (`loader`), the device tree
//! of a riscv64 or aarch64 guest read back with `azos_dtb` and by a walker of
//! its own (`dtb`), the PVH start_info of an x86_64 guest read back with the
//! x86 platform's own parser (`pvh`), and the three put together
//! (`life::prepare`, `life::boot`).

use crate::dtb::{self, Config, DtbError};
use crate::guest::{GuestMem, OutOfRam};
use crate::life::{self, Boot, Cpu, Entry, PrepareError, Setup};
use crate::loader::{self, Image, Isa, LoadError, Source, HOST};
use crate::mmio::WINDOW;
use crate::model::{self, Kind};
use crate::pvh::{self, PvhError};

/// The x86 platform's own reading of the boot information, the code the
/// guest kernel runs.
#[path = "../../../../arch/x86_64/src/firmware/bootinfo.rs"]
mod bootinfo;

const MIB: u64 = 1 << 20;

// ── guest RAM ────────────────────────────────────────────────────────────

/// Guest RAM at `base` that records every write.
struct Mem {
    base: u64,
    bytes: Vec<u8>,
    writes: Vec<(u64, usize)>,
}

impl Mem {
    fn new(base: u64, bytes: u64) -> Mem {
        Mem { base, bytes: vec![0; bytes as usize], writes: Vec::new() }
    }

    /// RAM that was used before: nothing is zero.
    fn dirty(base: u64, bytes: u64) -> Mem {
        Mem { base, bytes: vec![0xAA; bytes as usize], writes: Vec::new() }
    }

    fn get(&self, gpa: u64, len: usize) -> &[u8] {
        let at = (gpa - self.base) as usize;
        &self.bytes[at..at + len]
    }
}

impl GuestMem for Mem {
    fn range(&self) -> (u64, u64) {
        (self.base, self.bytes.len() as u64)
    }

    fn read(&self, gpa: u64, out: &mut [u8]) -> Result<(), OutOfRam> {
        if !self.contains(gpa, out.len() as u64) {
            return Err(OutOfRam);
        }
        out.copy_from_slice(self.get(gpa, out.len()));
        Ok(())
    }

    fn write(&mut self, gpa: u64, data: &[u8]) -> Result<(), OutOfRam> {
        if !self.contains(gpa, data.len() as u64) {
            return Err(OutOfRam);
        }
        self.writes.push((gpa, data.len()));
        let at = (gpa - self.base) as usize;
        self.bytes[at..at + data.len()].copy_from_slice(data);
        Ok(())
    }
}

// ── kernel files ─────────────────────────────────────────────────────────

/// A `PT_LOAD` to build.
#[derive(Clone)]
struct Seg {
    vaddr: u64,
    paddr: u64,
    data: Vec<u8>,
    memsz: u64,
    /// The segment starts at file offset 0: the ELF header and the program
    /// header table are its first bytes (the layout linkers write).
    with_header: bool,
}

impl Seg {
    fn new(addr: u64, data: Vec<u8>) -> Seg {
        let memsz = data.len() as u64;
        Seg { vaddr: addr, paddr: addr, data, memsz, with_header: false }
    }
}

struct Elf {
    machine: u16,
    entry: u64,
    segs: Vec<Seg>,
    /// A `PT_NOTE` holding these bytes.
    note: Option<Vec<u8>>,
    ty: u16,
    class: u8,
}

impl Elf {
    fn new(isa: Isa, entry: u64, segs: Vec<Seg>) -> Elf {
        Elf { machine: isa.machine(), entry, segs, note: None, ty: 2, class: 2 }
    }

    fn build(&self) -> Vec<u8> {
        let phnum = self.segs.len() + self.note.is_some() as usize;
        let hdr_len = 64 + phnum * 56;
        let mut file = vec![0u8; hdr_len];
        let mut phdrs: Vec<[u64; 7]> = Vec::new(); // type|flags<<32, off, vaddr, paddr, filesz, memsz, align
        for s in &self.segs {
            if s.with_header {
                assert!(phdrs.is_empty() && file.len() == hdr_len, "the header segment is the first");
                file.extend_from_slice(&s.data);
                phdrs.push([1 | 7 << 32, 0, s.vaddr, s.paddr, file.len() as u64, s.memsz.max(file.len() as u64), 4096]);
            } else {
                while file.len() % 4096 != 0 {
                    file.push(0);
                }
                phdrs.push([1 | 7 << 32, file.len() as u64, s.vaddr, s.paddr, s.data.len() as u64, s.memsz, 4096]);
                file.extend_from_slice(&s.data);
            }
        }
        if let Some(n) = &self.note {
            while file.len() % 4 != 0 {
                file.push(0);
            }
            phdrs.push([4 | 4 << 32, file.len() as u64, 0, 0, n.len() as u64, n.len() as u64, 4]);
            file.extend_from_slice(n);
        }
        file[..4].copy_from_slice(b"\x7fELF");
        file[4] = self.class;
        file[5] = 1;
        file[6] = 1;
        file[16..18].copy_from_slice(&self.ty.to_le_bytes());
        file[18..20].copy_from_slice(&self.machine.to_le_bytes());
        file[20..24].copy_from_slice(&1u32.to_le_bytes());
        file[24..32].copy_from_slice(&self.entry.to_le_bytes());
        file[32..40].copy_from_slice(&64u64.to_le_bytes());
        file[52..54].copy_from_slice(&64u16.to_le_bytes());
        file[54..56].copy_from_slice(&56u16.to_le_bytes());
        file[56..58].copy_from_slice(&(phnum as u16).to_le_bytes());
        for (i, p) in phdrs.iter().enumerate() {
            let at = 64 + i * 56;
            file[at..at + 4].copy_from_slice(&(p[0] as u32).to_le_bytes());
            file[at + 4..at + 8].copy_from_slice(&((p[0] >> 32) as u32).to_le_bytes());
            for (j, v) in p[1..].iter().enumerate() {
                file[at + 8 + j * 8..at + 16 + j * 8].copy_from_slice(&v.to_le_bytes());
            }
        }
        file
    }
}

/// An ELF note `Xen` / `XEN_ELFNOTE_PHYS32_ENTRY`.
fn pvh_note(entry: u32) -> Vec<u8> {
    let mut n = Vec::new();
    n.extend_from_slice(&4u32.to_le_bytes());
    n.extend_from_slice(&4u32.to_le_bytes());
    n.extend_from_slice(&18u32.to_le_bytes());
    n.extend_from_slice(b"Xen\0");
    n.extend_from_slice(&entry.to_le_bytes());
    n
}

/// A file read `chunk` bytes at a time; it counts what was asked of it.
struct Bytes {
    data: Vec<u8>,
    at: usize,
    chunk: usize,
    fail_at: Option<usize>,
}

impl Bytes {
    fn new(data: Vec<u8>) -> Bytes {
        Bytes { data, at: 0, chunk: usize::MAX, fail_at: None }
    }
}

impl Source for Bytes {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
        if self.fail_at.is_some_and(|f| self.at >= f) {
            return Err(());
        }
        let n = buf.len().min(self.chunk).min(self.data.len() - self.at);
        buf[..n].copy_from_slice(&self.data[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

/// The buffer the monitor lends the loader (`life::SCRATCH_BYTES`).
fn scratch() -> Vec<u8> {
    vec![0; life::SCRATCH_BYTES]
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed)).collect()
}

const RV_BASE: u64 = 0x8000_0000;

fn rv_kernel() -> (Elf, Vec<u8>, Vec<u8>) {
    let text = pattern(0x1800, 1);
    let data = pattern(0x300, 2);
    let mut s2 = Seg::new(RV_BASE + 0x20_3000, data.clone());
    s2.memsz = 0x2000; // .bss
    let elf = Elf::new(Isa::Riscv64, RV_BASE + 0x20_0010, vec![Seg::new(RV_BASE + 0x20_0000, text.clone()), s2]);
    (elf, text, data)
}

// ── the kernel loader ────────────────────────────────────────────────────

#[test]
fn segments_go_to_their_physical_addresses_and_bss_is_zero() {
    let (elf, text, data) = rv_kernel();
    let mut ram = Mem::dirty(RV_BASE, 8 * MIB);
    let img = loader::load(&mut Bytes::new(elf.build()), &mut ram, Isa::Riscv64, &mut scratch()).unwrap();
    assert_eq!(ram.get(RV_BASE + 0x20_0000, text.len()), &text[..]);
    assert_eq!(ram.get(RV_BASE + 0x20_3000, data.len()), &data[..]);
    assert!(ram.get(RV_BASE + 0x20_3000 + data.len() as u64, 0x2000 - data.len()).iter().all(|&b| b == 0), "the .bss");
    assert_eq!(ram.get(RV_BASE + 0x20_1800, 16), &[0xAA; 16], "bytes between segments are not touched");
    assert_eq!(img, Image { entry: RV_BASE + 0x20_0010, low: RV_BASE + 0x20_0000, high: RV_BASE + 0x20_5000 });
}

#[test]
fn the_entry_is_physical_when_the_kernel_links_high_and_loads_low() {
    // aarch64: the symbols are in the upper half, the bytes are loaded low.
    let high = 0xffff_ff80_0000_0000u64;
    let text = pattern(0x2000, 3);
    let mut seg = Seg::new(0x4008_0000, text);
    seg.vaddr = high + 0x4008_0000;
    let elf = Elf::new(Isa::Aarch64, high + 0x4008_0040, vec![seg]);
    let mut ram = Mem::new(0x4000_0000, 16 * MIB);
    let img = loader::load(&mut Bytes::new(elf.build()), &mut ram, Isa::Aarch64, &mut scratch()).unwrap();
    assert_eq!(img.entry, 0x4008_0040);
}

#[test]
fn a_segment_that_holds_the_headers_still_gets_them_and_the_bytes_after() {
    let text = pattern(0x500, 9);
    let mut seg = Seg::new(RV_BASE + 0x20_0000, text.clone());
    seg.with_header = true;
    let elf = Elf::new(Isa::Riscv64, RV_BASE + 0x20_0200, vec![seg]);
    let file = elf.build();
    let mut ram = Mem::new(RV_BASE, 4 * MIB);
    loader::load(&mut Bytes::new(file.clone()), &mut ram, Isa::Riscv64, &mut scratch()).unwrap();
    // The segment's file bytes are the whole prefix of the file.
    let n = 64 + 56 + text.len();
    assert_eq!(ram.get(RV_BASE + 0x20_0000, n), &file[..n]);
    assert_eq!(&ram.get(RV_BASE + 0x20_0000, 4)[..], b"\x7fELF");
}

#[test]
fn the_result_does_not_depend_on_how_the_file_is_chunked() {
    let (elf, ..) = rv_kernel();
    let file = elf.build();
    let mut whole = Mem::new(RV_BASE, 8 * MIB);
    let a = loader::load(&mut Bytes::new(file.clone()), &mut whole, Isa::Riscv64, &mut scratch()).unwrap();
    for chunk in [1, 7, 4095, 4097] {
        let mut ram = Mem::new(RV_BASE, 8 * MIB);
        let mut src = Bytes::new(file.clone());
        src.chunk = chunk;
        assert_eq!(loader::load(&mut src, &mut ram, Isa::Riscv64, &mut scratch()), Ok(a), "chunk {chunk}");
        assert!(ram.bytes == whole.bytes, "chunk {chunk}");
    }
}

#[test]
fn the_loader_stops_reading_where_the_segments_end() {
    let (elf, ..) = rv_kernel();
    let mut file = elf.build();
    let kernel_end = file.len();
    file.extend_from_slice(&[0x55; 100_000]); // section headers, symbols, debug info
    let mut src = Bytes::new(file);
    let mut ram = Mem::new(RV_BASE, 8 * MIB);
    loader::load(&mut src, &mut ram, Isa::Riscv64, &mut scratch()).unwrap();
    assert!(src.at <= kernel_end, "read {} bytes of a kernel that ends at {kernel_end}", src.at);
}

fn load_err(elf: &Elf, isa: Isa, ram: &mut Mem) -> LoadError {
    loader::load(&mut Bytes::new(elf.build()), ram, isa, &mut scratch()).unwrap_err()
}

#[test]
fn what_is_not_a_kernel_of_this_isa_is_refused() {
    let (elf, ..) = rv_kernel();
    let mut ram = Mem::new(RV_BASE, 8 * MIB);
    assert_eq!(load_err(&elf, Isa::Aarch64, &mut ram), LoadError::Machine);
    let mut e = rv_kernel().0;
    e.ty = 3; // ET_DYN
    assert_eq!(load_err(&e, Isa::Riscv64, &mut ram), LoadError::NotElf);
    let mut e = rv_kernel().0;
    e.class = 1; // ELFCLASS32
    assert_eq!(load_err(&e, Isa::Riscv64, &mut ram), LoadError::NotElf);
    let mut src = Bytes::new(b"#!/bin/sh\n".repeat(100));
    assert_eq!(loader::load(&mut src, &mut ram, Isa::Riscv64, &mut scratch()), Err(LoadError::NotElf));
    assert!(ram.writes.is_empty());
}

#[test]
fn a_file_that_ends_early_or_fails_to_read_is_refused() {
    let file = rv_kernel().0.build();
    let mut ram = Mem::new(RV_BASE, 8 * MIB);
    for cut in [10, 64, 100, 5000] {
        let r = loader::load(&mut Bytes::new(file[..cut].to_vec()), &mut ram, Isa::Riscv64, &mut scratch());
        assert_eq!(r, Err(LoadError::Truncated), "cut at {cut}");
    }
    let mut src = Bytes::new(file);
    src.fail_at = Some(4096);
    assert_eq!(loader::load(&mut src, &mut ram, Isa::Riscv64, &mut scratch()), Err(LoadError::Read));
}

#[test]
fn a_segment_outside_guest_ram_is_refused_before_a_byte_is_written() {
    // The first segment is inside RAM and its bytes come first in the file;
    // the second reaches past the end.
    let ok = Seg::new(RV_BASE + 0x1000, pattern(0x1000, 4));
    let mut bad = Seg::new(RV_BASE + 4 * MIB - 0x800, pattern(0x1000, 5));
    bad.memsz = 0x1000;
    let elf = Elf::new(Isa::Riscv64, RV_BASE + 0x1000, vec![ok, bad]);
    let mut ram = Mem::new(RV_BASE, 4 * MIB);
    assert_eq!(load_err(&elf, Isa::Riscv64, &mut ram), LoadError::OutOfRam);
    assert!(ram.writes.is_empty(), "RAM was written: {:?}", ram.writes);
}

#[test]
fn a_segment_below_ram_or_wrapping_the_address_space_is_refused() {
    let mut ram = Mem::new(RV_BASE, 4 * MIB);
    let below = Elf::new(Isa::Riscv64, 0x1000, vec![Seg::new(0x1000, pattern(64, 1))]);
    assert_eq!(load_err(&below, Isa::Riscv64, &mut ram), LoadError::OutOfRam);
    let mut wrap = Seg::new(0x1000, pattern(64, 1));
    wrap.paddr = u64::MAX - 0x100;
    wrap.memsz = 0x1000;
    let wrap = Elf::new(Isa::Riscv64, 0x1000, vec![wrap]);
    assert_eq!(load_err(&wrap, Isa::Riscv64, &mut ram), LoadError::OutOfRam);
    assert!(ram.writes.is_empty());
}

#[test]
fn segments_that_overlap_or_lie_about_their_size_are_refused() {
    let mut ram = Mem::new(RV_BASE, 4 * MIB);
    let a = Seg::new(RV_BASE + 0x1000, pattern(0x2000, 1));
    let b = Seg::new(RV_BASE + 0x2000, pattern(0x2000, 2));
    let e = Elf::new(Isa::Riscv64, RV_BASE + 0x1000, vec![a, b]);
    assert_eq!(load_err(&e, Isa::Riscv64, &mut ram), LoadError::Overlap);
    // filesz > memsz: the bytes would run past the segment.
    let mut s = Seg::new(RV_BASE + 0x1000, pattern(0x2000, 1));
    s.memsz = 0x100;
    let e = Elf::new(Isa::Riscv64, RV_BASE + 0x1000, vec![s]);
    assert_eq!(load_err(&e, Isa::Riscv64, &mut ram), LoadError::BadSegment);
    assert!(ram.writes.is_empty());
}

#[test]
fn an_entry_outside_every_segment_is_refused() {
    let mut ram = Mem::new(RV_BASE, 4 * MIB);
    let e = Elf::new(Isa::Riscv64, RV_BASE + 0x9000, vec![Seg::new(RV_BASE + 0x1000, pattern(0x100, 1))]);
    assert_eq!(load_err(&e, Isa::Riscv64, &mut ram), LoadError::BadEntry);
}

#[test]
fn a_program_header_table_a_linker_would_not_write_is_refused() {
    let mut ram = Mem::new(RV_BASE, 4 * MIB);
    let mut file = rv_kernel().0.build();
    file[32..40].copy_from_slice(&128u64.to_le_bytes()); // e_phoff
    assert_eq!(loader::load(&mut Bytes::new(file), &mut ram, Isa::Riscv64, &mut scratch()), Err(LoadError::Phdrs));
    let mut file = rv_kernel().0.build();
    file[54..56].copy_from_slice(&32u16.to_le_bytes()); // e_phentsize
    assert_eq!(loader::load(&mut Bytes::new(file), &mut ram, Isa::Riscv64, &mut scratch()), Err(LoadError::Phdrs));
    let mut file = rv_kernel().0.build();
    file[56..58].copy_from_slice(&0u16.to_le_bytes()); // no phdrs
    assert_eq!(loader::load(&mut Bytes::new(file), &mut ram, Isa::Riscv64, &mut scratch()), Err(LoadError::Phdrs));
    let many: Vec<Seg> = (0..=loader::MAX_LOADS as u64).map(|i| Seg::new(RV_BASE + i * 0x1000, pattern(16, 1))).collect();
    let e = Elf::new(Isa::Riscv64, RV_BASE, many);
    assert_eq!(load_err(&e, Isa::Riscv64, &mut ram), LoadError::Loads);
    let none = Elf::new(Isa::Riscv64, RV_BASE, vec![]);
    assert_eq!(load_err(&none, Isa::Riscv64, &mut ram), LoadError::Phdrs);
    assert!(ram.writes.is_empty());
}

#[test]
fn an_x86_kernel_enters_at_its_pvh_note() {
    let text = pattern(0x1000, 6);
    let mut e = Elf::new(Isa::X86_64, 0xffff_ffff_8010_0000, vec![Seg::new(MIB, text)]);
    e.note = Some(pvh_note(MIB as u32 + 0x40));
    let mut ram = Mem::new(0, 8 * MIB);
    let img = loader::load(&mut Bytes::new(e.build()), &mut ram, Isa::X86_64, &mut scratch()).unwrap();
    assert_eq!(img.entry, MIB + 0x40, "the 32-bit entry, not the 64-bit e_entry (which lies in no segment)");
}

#[test]
fn an_x86_kernel_without_a_usable_pvh_entry_is_refused() {
    let mut ram = Mem::new(0, 8 * MIB);
    let e = Elf::new(Isa::X86_64, MIB, vec![Seg::new(MIB, pattern(0x100, 6))]);
    assert_eq!(load_err(&e, Isa::X86_64, &mut ram), LoadError::NoPvhEntry);
    let mut e = Elf::new(Isa::X86_64, MIB, vec![Seg::new(MIB, pattern(0x100, 6))]);
    e.note = Some(pvh_note(0x40_0000)); // in no segment
    assert_eq!(load_err(&e, Isa::X86_64, &mut ram), LoadError::BadEntry);
    // A note of another owner or type is not the entry.
    let mut other = pvh_note(MIB as u32);
    other[8..12].copy_from_slice(&17u32.to_le_bytes());
    let mut e = Elf::new(Isa::X86_64, MIB, vec![Seg::new(MIB, pattern(0x100, 6))]);
    e.note = Some(other);
    assert_eq!(load_err(&e, Isa::X86_64, &mut ram), LoadError::NoPvhEntry);
}

// ── the device tree ──────────────────────────────────────────────────────

/// The flattened tree, read by a parser that shares nothing with the builder.
struct Node {
    path: String,
    props: Vec<(String, Vec<u8>)>,
}

struct Tree(Vec<Node>);

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
}

fn parse_tree(b: &[u8]) -> Tree {
    assert_eq!(be32(b, 0), 0xd00d_feed, "magic");
    assert_eq!(be32(b, 4) as usize, b.len(), "totalsize");
    assert_eq!(b.len() % 4, 0);
    let (off_struct, off_strings, off_rsv) = (be32(b, 8) as usize, be32(b, 12) as usize, be32(b, 16) as usize);
    assert_eq!((be32(b, 20), be32(b, 24), be32(b, 28)), (17, 16, 0), "version, last compatible, boot cpu");
    let strings_end = off_strings + be32(b, 32) as usize;
    assert!(strings_end <= b.len() && b.len() - strings_end < 4, "the strings end the blob (up to padding)");
    assert_eq!(be32(b, 36) as usize, off_strings - off_struct, "size_dt_struct");
    assert_eq!(off_rsv % 8, 0);
    assert!(b[off_rsv..off_rsv + 16].iter().all(|&x| x == 0), "an empty memory reservation block");
    assert_eq!(off_struct, off_rsv + 16);
    let strs = &b[off_strings..];
    let mut nodes: Vec<Node> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut at = off_struct;
    loop {
        let tok = be32(b, at);
        at += 4;
        match tok {
            1 => {
                let len = b[at..].iter().position(|&c| c == 0).unwrap();
                let name = std::str::from_utf8(&b[at..at + len]).unwrap();
                at = (at + len + 1 + 3) & !3;
                let path = match stack.last() {
                    None => String::from("/"),
                    Some(&p) if nodes[p].path == "/" => format!("/{name}"),
                    Some(&p) => format!("{}/{name}", nodes[p].path),
                };
                nodes.push(Node { path, props: Vec::new() });
                stack.push(nodes.len() - 1);
            }
            2 => {
                stack.pop().unwrap();
            }
            3 => {
                let (len, nameoff) = (be32(b, at) as usize, be32(b, at + 4) as usize);
                at += 8;
                let nl = strs[nameoff..].iter().position(|&c| c == 0).unwrap();
                let name = std::str::from_utf8(&strs[nameoff..nameoff + nl]).unwrap().to_string();
                let data = b[at..at + len].to_vec();
                at = (at + len + 3) & !3;
                let cur = *stack.last().unwrap();
                assert!(!nodes[cur].props.iter().any(|(n, _)| *n == name), "{}: {name} twice", nodes[cur].path);
                nodes[cur].props.push((name, data));
            }
            9 => break,
            t => panic!("token {t} at {at}"),
        }
    }
    assert!(stack.is_empty());
    assert_eq!(at, off_strings, "the structure block ends where the strings begin");
    // Every string of the table is used once and named once.
    let names: Vec<&[u8]> = strs.split(|&c| c == 0).filter(|s| !s.is_empty()).collect();
    for (i, n) in names.iter().enumerate() {
        assert!(!names[i + 1..].contains(n), "string {:?} twice", std::str::from_utf8(n));
    }
    Tree(nodes)
}

impl Tree {
    fn node(&self, path: &str) -> &Node {
        self.0.iter().find(|n| n.path == path).unwrap_or_else(|| panic!("no node {path}"))
    }

    fn has(&self, path: &str) -> bool {
        self.0.iter().any(|n| n.path == path)
    }

    fn children(&self, path: &str) -> Vec<&Node> {
        let prefix = if path == "/" { String::from("/") } else { format!("{path}/") };
        self.0.iter().filter(|n| n.path.starts_with(&prefix) && !n.path[prefix.len()..].contains('/') && n.path != path).collect()
    }
}

impl Node {
    fn raw(&self, name: &str) -> Option<&[u8]> {
        self.props.iter().find(|(n, _)| n == name).map(|(_, d)| &d[..])
    }

    fn str(&self, name: &str) -> String {
        let d = self.raw(name).unwrap_or_else(|| panic!("{}: no {name}", self.path));
        assert_eq!(d.last(), Some(&0), "{name} is a string");
        String::from_utf8(d[..d.len() - 1].to_vec()).unwrap()
    }

    fn list(&self, name: &str) -> Vec<String> {
        let d = self.raw(name).unwrap_or_else(|| panic!("{}: no {name}", self.path));
        d.split(|&c| c == 0).take_while(|s| !s.is_empty()).map(|s| String::from_utf8(s.to_vec()).unwrap()).collect()
    }

    fn cells(&self, name: &str) -> Vec<u32> {
        let d = self.raw(name).unwrap_or_else(|| panic!("{}: no {name}", self.path));
        assert_eq!(d.len() % 4, 0);
        d.chunks(4).map(|c| u32::from_be_bytes(c.try_into().unwrap())).collect()
    }

    fn u32(&self, name: &str) -> u32 {
        let c = self.cells(name);
        assert_eq!(c.len(), 1, "{}: {name}", self.path);
        c[0]
    }
}

const ALL: [Option<Kind>; 3] = [Some(Kind::Console), Some(Kind::Blk), Some(Kind::Net)];

fn cfg<'a>(isa: Isa, cpus: usize, devices: &'a [Option<Kind>], args: &'a [u8]) -> Config<'a> {
    let base = match isa {
        Isa::Riscv64 => 0x8000_0000,
        Isa::Aarch64 => 0x4000_0000,
        Isa::X86_64 => 0,
    };
    Config { isa, ram_base: base, ram_bytes: 256 * MIB, cpus, timebase_hz: 10_000_000, devices, args }
}

fn tree_of(c: &Config) -> (Vec<u8>, Tree) {
    let mut out = vec![0u8; dtb::MAX_BYTES];
    let n = dtb::build(c, &mut out).unwrap();
    out.truncate(n);
    let t = parse_tree(&out);
    (out, t)
}

/// `reg` of two address and two size cells.
fn reg2(n: &Node) -> Vec<(u64, u64)> {
    n.cells("reg").chunks(4).map(|c| ((c[0] as u64) << 32 | c[1] as u64, (c[2] as u64) << 32 | c[3] as u64)).collect()
}

#[test]
fn the_device_models_read_their_windows_and_lines_from_the_platform_table_of_the_host() {
    let p = dtb::platform(HOST);
    assert_eq!(p.mmio_base, model::MMIO_BASE);
    for i in 0..model::MAX_DEVICES {
        assert_eq!(model::window_base(i), dtb::device_base(&p, i));
        assert_eq!(model::irq_line(i), dtb::device_line(&p, i));
    }
}

#[test]
fn the_tree_parses_back_with_the_kernels_own_parser() {
    for (isa, cpus) in [(Isa::Riscv64, 4), (Isa::Aarch64, 3), (Isa::Riscv64, 1), (Isa::Aarch64, 16)] {
        let c = cfg(isa, cpus, &ALL, b"console=hvc0 quiet");
        let (blob, _) = tree_of(&c);
        let info = unsafe { azos_dtb::dtb_parse(blob.as_ptr()) }.unwrap_or_else(|| panic!("{isa:?} did not parse"));
        assert_eq!((info.mem_base as u64, info.mem_size as u64), (c.ram_base, c.ram_bytes), "{isa:?}");
        assert_eq!(info.num_cpus, cpus, "{isa:?}");
        if isa == Isa::Riscv64 {
            assert_eq!(info.timer_freq, 10_000_000);
            assert_eq!(info.plic_base as u64, dtb::platform(isa).intc_base);
        }
        let mut regs = [u64::MAX; 16];
        assert_eq!(unsafe { azos_dtb::dtb_cpu_regs(blob.as_ptr(), &mut regs) }, Some(cpus));
        assert_eq!(&regs[..cpus], &(0..cpus as u64).collect::<Vec<_>>()[..], "hart ids / MPIDR affinities");
        let mut args = [0u8; 64];
        let n = unsafe { azos_dtb::dtb_bootargs(blob.as_ptr(), &mut args) }.unwrap();
        assert_eq!(&args[..n], b"console=hvc0 quiet");
    }
}

#[test]
fn every_virtio_device_of_the_row_has_a_node_at_the_window_and_line_the_model_serves() {
    for isa in [Isa::Riscv64, Isa::Aarch64] {
        // Device 1 has no model: a hole in the row, no node, and the indices
        // after it keep their windows.
        let devices = [Some(Kind::Console), None, Some(Kind::Blk), Some(Kind::Net)];
        let (blob, _) = tree_of(&cfg(isa, 2, &devices, b""));
        let p = dtb::platform(isa);
        let mut seen = Vec::new();
        let n = unsafe {
            azos_dtb::dtb_devices(blob.as_ptr(), &mut |d| {
                if d.compatible.starts_with(b"virtio,mmio") {
                    seen.push((d.name.to_vec(), d.base, d.size, d.irq));
                }
            })
        };
        assert!(n.is_some());
        let want: Vec<_> = [0usize, 2, 3]
            .iter()
            .map(|&i| {
                let base = p.mmio_base + i as u64 * WINDOW;
                (format!("virtio_mmio@{base:x}").into_bytes(), base, WINDOW, p.irq_base + i as u32)
            })
            .collect();
        assert_eq!(seen, want, "{isa:?}");
    }
}

#[test]
fn riscv_cpus_are_brought_up_through_sbi_and_see_a_plic() {
    let (_, t) = tree_of(&cfg(Isa::Riscv64, 4, &ALL, b""));
    let cpus = t.node("/cpus");
    assert_eq!((cpus.u32("#address-cells"), cpus.u32("#size-cells")), (1, 0));
    assert_eq!(cpus.u32("timebase-frequency"), 10_000_000);
    let kids = t.children("/cpus");
    assert_eq!(kids.len(), 4);
    let plic = t.node("/soc/plic@c000000");
    assert_eq!(plic.list("compatible"), ["sifive,plic-1.0.0", "riscv,plic0"]);
    assert_eq!(reg2(plic), [(0x0c00_0000, 0x60_0000)]);
    assert_eq!(plic.u32("#interrupt-cells"), 1);
    assert!(plic.raw("interrupt-controller").is_some());
    let mut ext = Vec::new();
    for k in 0..4u32 {
        let cpu = t.node(&format!("/cpus/cpu@{k}"));
        assert_eq!(cpu.u32("reg"), k);
        assert_eq!(cpu.str("device_type"), "cpu");
        assert_eq!(cpu.str("status"), "okay");
        assert_eq!(cpu.str("enable-method"), "sbi");
        assert_eq!(cpu.str("riscv,isa"), "rv64imac");
        let intc = t.node(&format!("/cpus/cpu@{k}/interrupt-controller"));
        assert_eq!(intc.str("compatible"), "riscv,cpu-intc");
        ext.extend([intc.u32("phandle"), 9]);
    }
    assert_eq!(plic.cells("interrupts-extended"), ext, "context k is hart k's supervisor external interrupt");
    let phandles: Vec<u32> = t.0.iter().filter_map(|n| n.raw("phandle").map(|_| n.u32("phandle"))).collect();
    let mut uniq = phandles.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), phandles.len(), "phandles are unique");
    assert_eq!(t.node("/").u32("interrupt-parent"), plic.u32("phandle"));
    assert!(plic.u32("riscv,ndev") >= dtb::platform(Isa::Riscv64).irq_base + 15, "a source for every device the row can list");
    for d in t.children("/soc").iter().filter(|n| n.path.contains("virtio_mmio")) {
        assert_eq!(d.str("compatible"), "virtio,mmio");
        assert!(d.raw("interrupts").is_some());
    }
    assert!(!t.has("/psci"), "no PSCI on riscv");
}

#[test]
fn aarch64_cpus_are_brought_up_through_psci_hvc_and_see_a_gicv3() {
    let (_, t) = tree_of(&cfg(Isa::Aarch64, 4, &ALL, b""));
    let psci = t.node("/psci");
    assert!(psci.list("compatible").contains(&"arm,psci-0.2".to_string()));
    assert_eq!(psci.str("method"), "hvc");
    for k in 0..4u32 {
        let cpu = t.node(&format!("/cpus/cpu@{k}"));
        assert_eq!(cpu.u32("reg"), k);
        assert_eq!(cpu.str("enable-method"), "psci");
        assert_eq!(cpu.str("device_type"), "cpu");
    }
    assert!(t.node("/cpus").raw("timebase-frequency").is_none(), "the architectural timer is read from the counter");
    let timer = t.node("/timer");
    assert_eq!(timer.str("compatible"), "arm,armv8-timer");
    let irqs = timer.cells("interrupts");
    let ppis: Vec<u32> = irqs.chunks(3).map(|c| c[1]).collect();
    assert_eq!(ppis, [13, 14, 11, 10]);
    assert!(irqs.chunks(3).all(|c| c[0] == 1), "PPIs");
    let gic = t.node("/soc/interrupt-controller@8000000");
    assert_eq!(gic.str("compatible"), "arm,gic-v3");
    assert_eq!(gic.u32("#interrupt-cells"), 3);
    // Distributor, then one redistributor frame (two 64 KiB pages) per vCPU.
    assert_eq!(reg2(gic), [(0x0800_0000, 0x1_0000), (0x080a_0000, 4 * 0x2_0000)]);
    assert_eq!(t.node("/").u32("interrupt-parent"), gic.u32("phandle"));
    // A GIC interrupt id from 32 up is SPI id - 32, level-high.
    let blk = t.node(&format!("/soc/virtio_mmio@{:x}", 0x0a00_0000u64 + WINDOW));
    assert_eq!(blk.cells("interrupts"), [0, 48 + 1 - 32, 4]);
    assert!(blk.raw("dma-coherent").is_some());
}

#[test]
fn memory_chosen_and_the_soc_bus_are_described() {
    for isa in [Isa::Riscv64, Isa::Aarch64] {
        let c = cfg(isa, 2, &ALL, b"azos.mode=guest");
        let (_, t) = tree_of(&c);
        let root = t.node("/");
        assert_eq!((root.u32("#address-cells"), root.u32("#size-cells")), (2, 2));
        let mem = t.node(&format!("/memory@{:x}", c.ram_base));
        assert_eq!(mem.str("device_type"), "memory");
        assert_eq!(reg2(mem), [(c.ram_base, c.ram_bytes)]);
        let chosen = t.node("/chosen");
        assert_eq!(chosen.str("bootargs"), "azos.mode=guest");
        // The guest's console is device 0 of the row.
        let con = format!("/soc/virtio_mmio@{:x}", dtb::platform(isa).mmio_base);
        assert_eq!(chosen.str("stdout-path"), con);
        assert!(t.has(&con));
        let soc = t.node("/soc");
        assert!(soc.raw("ranges").is_some(), "children are addressed by CPU physical addresses");
        assert_eq!(soc.str("compatible"), "simple-bus");
    }
}

#[test]
fn a_row_without_a_console_or_arguments_has_neither_property() {
    let (_, t) = tree_of(&cfg(Isa::Riscv64, 1, &[Some(Kind::Blk)], b""));
    let chosen = t.node("/chosen");
    assert!(chosen.raw("bootargs").is_none() && chosen.raw("stdout-path").is_none());
    let (_, t) = tree_of(&cfg(Isa::Aarch64, 1, &[None, Some(Kind::Net), Some(Kind::Console)], b""));
    let con = format!("/soc/virtio_mmio@{:x}", 0x0a00_0000u64 + 2 * WINDOW);
    assert_eq!(t.node("/chosen").str("stdout-path"), con, "the console's index in the row, not the first device");
}

#[test]
fn the_largest_guest_fits_the_buffer_and_a_smaller_buffer_is_an_error() {
    let full: Vec<Option<Kind>> = (0..model::MAX_DEVICES).map(|i| Some([Kind::Console, Kind::Blk, Kind::Net][i % 3])).collect();
    let args = [b'a'; 256];
    for isa in [Isa::Riscv64, Isa::Aarch64] {
        let c = cfg(isa, dtb::MAX_CPUS, &full, &args);
        let mut out = vec![0u8; dtb::MAX_BYTES];
        let n = dtb::build(&c, &mut out).unwrap();
        assert!(n < dtb::MAX_BYTES - 1024, "{isa:?}: {n} bytes leaves room");
        parse_tree(&out[..n]);
        for size in [0, 40, 100, n - 1] {
            let mut small = vec![0u8; size];
            assert_eq!(dtb::build(&c, &mut small), Err(DtbError::Full), "{isa:?} buffer {size}");
        }
        let mut exact = vec![0u8; n];
        assert_eq!(dtb::build(&c, &mut exact), Ok(n), "{isa:?}");
    }
}

#[test]
fn a_configuration_with_no_tree_is_refused() {
    let mut out = vec![0u8; dtb::MAX_BYTES];
    assert_eq!(dtb::build(&cfg(Isa::X86_64, 1, &ALL, b""), &mut out), Err(DtbError::BadConfig));
    assert_eq!(dtb::build(&cfg(Isa::Riscv64, 0, &ALL, b""), &mut out), Err(DtbError::BadConfig));
    assert_eq!(dtb::build(&cfg(Isa::Riscv64, dtb::MAX_CPUS + 1, &ALL, b""), &mut out), Err(DtbError::BadConfig));
    let mut c = cfg(Isa::Aarch64, 1, &ALL, b"");
    c.ram_bytes = 0;
    assert_eq!(dtb::build(&c, &mut out), Err(DtbError::BadConfig));
    let too_many = [Some(Kind::Blk); model::MAX_DEVICES + 1];
    assert_eq!(dtb::build(&cfg(Isa::Aarch64, 1, &too_many, b""), &mut out), Err(DtbError::BadConfig));
}

// ── PVH ──────────────────────────────────────────────────────────────────

fn pvh_blob(ram: u64, devices: &[(u64, u64, u32)], args: &[u8]) -> Result<Vec<u8>, PvhError> {
    let mut out = vec![0u8; pvh::MAX_BYTES];
    let n = pvh::build(&pvh::Info { ram_bytes: ram, devices, args }, &mut out)?;
    out.truncate(n);
    Ok(out)
}

fn cstr(b: &[u8]) -> String {
    let n = b.iter().position(|&c| c == 0).unwrap();
    String::from_utf8(b[..n].to_vec()).unwrap()
}

#[test]
fn the_start_info_is_what_the_x86_kernel_expects() {
    let p = dtb::platform(Isa::X86_64);
    let devs: Vec<_> = (0..3).map(|i| (p.mmio_base + i * WINDOW, WINDOW, p.irq_base + i as u32)).collect();
    let blob = pvh_blob(64 * MIB, &devs, b"console=ttyS0 root=/dev/vda").unwrap();
    // Read through the platform's own layout of the record.
    assert_eq!(std::mem::size_of::<bootinfo::HvmStartInfo>(), 56);
    let si: bootinfo::HvmStartInfo = unsafe { std::ptr::read_unaligned(blob.as_ptr() as *const _) };
    assert_eq!((si.magic, si.version, si.flags, si.nr_modules), (bootinfo::PVH_MAGIC, 1, 0, 0));
    assert_eq!((si.modlist_paddr, si.rsdp_paddr), (0, 0));
    let at = |paddr: u64| (paddr - pvh::BASE) as usize;
    let map: Vec<bootinfo::MemEntry> = (0..si.memmap_entries as usize)
        .map(|i| unsafe { std::ptr::read_unaligned(blob[at(si.memmap_paddr) + i * 24..].as_ptr() as *const _) })
        .collect();
    // RAM, the legacy hole, RAM: the kernel's admission sees [0, 64 MiB) and one hole.
    assert_eq!(bootinfo::ram_span(&map, u64::MAX), Some((0, 64 * MIB)));
    let mut holes = Vec::new();
    bootinfo::for_each_hole(&map, 64 * MIB, |s, l| holes.push((s, l)));
    assert_eq!(holes, [(0xA_0000, 0x6_0000)]);
    assert!(bootinfo::is_ram(&map, MIB, 63 * MIB) && !bootinfo::is_ram(&map, 0x9_0000, 0x2_0000));
    // The command line: the platform's parser finds every device, in order.
    let cmd = cstr(&blob[at(si.cmdline_paddr)..]);
    assert!(cmd.ends_with("console=ttyS0 root=/dev/vda"), "{cmd}");
    let mut found = [bootinfo::VirtioMmio { base: 0, size: 0, gsi: 0 }; 8];
    let (n, bad) = bootinfo::parse_virtio_mmio(cmd.as_bytes(), &mut found);
    assert_eq!((n, bad), (3, 0), "{cmd}");
    for (i, d) in found[..3].iter().enumerate() {
        assert_eq!((d.base, d.size, d.gsi), (devs[i].0, devs[i].1, devs[i].2));
    }
    assert!(blob.len() <= pvh::MAX_BYTES && si.cmdline_paddr < pvh::BASE + blob.len() as u64);
}

#[test]
fn the_pvh_blob_is_refused_when_it_cannot_be_right() {
    assert_eq!(pvh_blob(MIB, &[], b""), Err(PvhError::RamTooSmall));
    assert_eq!(pvh_blob(0x8_0000, &[], b""), Err(PvhError::RamTooSmall));
    assert_eq!(pvh_blob(8 * MIB, &[], &[b'x'; pvh::MAX_BYTES]), Err(PvhError::Full));
    let p = dtb::platform(Isa::X86_64);
    let many: Vec<_> = (0..model::MAX_DEVICES as u64).map(|i| (p.mmio_base + i * WINDOW, WINDOW, p.irq_base + i as u32)).collect();
    assert!(pvh_blob(8 * MIB, &many, &[b'x'; 256]).is_ok(), "sixteen devices and a long line fit");
    let mut small = vec![0u8; 100];
    assert_eq!(pvh::build(&pvh::Info { ram_bytes: 8 * MIB, devices: &[], args: b"" }, &mut small), Err(PvhError::Full));
}

// ── a guest, prepared and started ────────────────────────────────────────

fn setup<'a>(isa: Isa, cpus: usize, args: &'a [u8]) -> Setup<'a> {
    Setup { isa, cpus, timebase_hz: 10_000_000, devices: &ALL, args }
}

fn kernel_at(isa: Isa, base: u64, ram_bytes: u64) -> (Mem, Vec<u8>) {
    let ram = Mem::new(if isa == Isa::X86_64 { 0 } else { base }, ram_bytes);
    let at = match isa {
        Isa::Riscv64 => base + 0x20_0000,
        Isa::Aarch64 => base + 0x8_0000,
        Isa::X86_64 => MIB,
    };
    let mut e = Elf::new(isa, at + 0x10, vec![Seg::new(at, pattern(0x3000, 8))]);
    if isa == Isa::X86_64 {
        e.note = Some(pvh_note(at as u32 + 0x10));
    }
    (ram, e.build())
}

#[test]
fn a_riscv_or_arm_guest_gets_its_tree_below_the_kernel_and_its_address() {
    for (isa, base) in [(Isa::Riscv64, 0x8000_0000u64), (Isa::Aarch64, 0x4000_0000)] {
        let (mut ram, file) = kernel_at(isa, base, 64 * MIB);
        let entry = life::prepare(&mut Bytes::new(file), &mut ram, &setup(isa, 2, b"quiet"), &mut scratch()).unwrap();
        let kernel = if isa == Isa::Riscv64 { base + 0x20_0010 } else { base + 0x8_0010 };
        assert_eq!(entry, Entry { pc: kernel, arg: base }, "the tree is where firmware would be");
        let blob = ram.get(entry.arg, ram.bytes.len() - (entry.arg - base) as usize).to_vec();
        let info = unsafe { azos_dtb::dtb_parse(blob.as_ptr()) }.unwrap();
        assert_eq!((info.mem_base as u64, info.mem_size as u64, info.num_cpus), (base, 64 * MIB, 2));
        // The tree does not overlap the kernel.
        let total = u32::from_be_bytes(blob[4..8].try_into().unwrap()) as u64;
        assert!(entry.arg + total <= kernel & !0xFFF);
    }
}

#[test]
fn a_guest_asked_for_less_memory_is_told_so_and_its_kernel_must_fit_in_it() {
    let base = 0x8000_0000u64;
    let (mut full, file) = kernel_at(Isa::Riscv64, base, 64 * MIB);
    {
        let mut view = crate::ctl::Limited::new(&mut full, 16 * MIB);
        let entry = life::prepare(&mut Bytes::new(file.clone()), &mut view, &setup(Isa::Riscv64, 1, b""), &mut scratch()).unwrap();
        let blob = view_get(&view, entry.arg);
        let info = unsafe { azos_dtb::dtb_parse(blob.as_ptr()) }.unwrap();
        assert_eq!((info.mem_base as u64, info.mem_size as u64), (base, 16 * MIB), "the tree names the smaller memory");
    }
    // A kernel linked above the visible memory is refused as one outside RAM.
    let mut full = Mem::new(base, 64 * MIB);
    let mut view = crate::ctl::Limited::new(&mut full, 2 * MIB);
    assert_eq!(
        life::prepare(&mut Bytes::new(file), &mut view, &setup(Isa::Riscv64, 1, b""), &mut scratch()),
        Err(PrepareError::Kernel(LoadError::OutOfRam))
    );
}

fn view_get(view: &dyn GuestMem, at: u64) -> Vec<u8> {
    let mut v = vec![0u8; 4096];
    view.read(at, &mut v).unwrap();
    v
}

#[test]
fn the_tree_goes_above_the_kernel_when_nothing_is_free_below_it() {
    // The kernel starts at the first byte of RAM.
    let base = 0x8000_0000u64;
    let mut ram = Mem::new(base, 8 * MIB);
    let e = Elf::new(Isa::Riscv64, base, vec![Seg::new(base, pattern(0x2100, 8))]);
    let entry = life::prepare(&mut Bytes::new(e.build()), &mut ram, &setup(Isa::Riscv64, 1, b""), &mut scratch()).unwrap();
    assert_eq!(entry.arg, base + 0x3000, "page-aligned, right above the image");
    assert!(unsafe { azos_dtb::dtb_parse(ram.get(entry.arg, 4096).as_ptr()) }.is_some());
    // And with no room above it either, the guest is not started.
    let mut ram = Mem::new(base, 0x2800);
    let e = Elf::new(Isa::Riscv64, base, vec![Seg::new(base, pattern(0x2100, 8))]);
    assert_eq!(
        life::prepare(&mut Bytes::new(e.build()), &mut ram, &setup(Isa::Riscv64, 1, b""), &mut scratch()),
        Err(PrepareError::NoRoom)
    );
}

#[test]
fn an_x86_guest_gets_the_start_info_at_its_fixed_place_and_enters_at_the_pvh_entry() {
    let (mut ram, file) = kernel_at(Isa::X86_64, 0, 32 * MIB);
    let entry = life::prepare(&mut Bytes::new(file), &mut ram, &setup(Isa::X86_64, 2, b"quiet"), &mut scratch()).unwrap();
    assert_eq!(entry, Entry { pc: MIB + 0x10, arg: pvh::BASE });
    assert_eq!(u32::from_le_bytes(ram.get(pvh::BASE, 4).try_into().unwrap()), pvh::MAGIC);
    let cmd = cstr(ram.get(pvh::BASE + 128, 400));
    assert!(cmd.contains("virtio_mmio.device=0x200@0xd0000000:5") && cmd.ends_with("quiet"), "{cmd}");
}

#[test]
fn an_x86_guest_whose_kernel_would_cover_the_start_info_is_not_started() {
    let mut ram = Mem::new(0, 32 * MIB);
    let mut e = Elf::new(Isa::X86_64, 0x4000, vec![Seg::new(0x4000, pattern(0x3000, 8))]);
    e.note = Some(pvh_note(0x4010));
    assert_eq!(
        life::prepare(&mut Bytes::new(e.build()), &mut ram, &setup(Isa::X86_64, 1, b""), &mut scratch()),
        Err(PrepareError::NoRoom)
    );
    // An x86 guest's memory starts at 0.
    let (_, file) = kernel_at(Isa::X86_64, 0, 0);
    let mut shifted = Mem::new(MIB, 32 * MIB);
    assert!(life::prepare(&mut Bytes::new(file), &mut shifted, &setup(Isa::X86_64, 1, b""), &mut scratch()).is_err());
}

#[test]
fn a_refused_kernel_is_a_prepare_error_with_a_reason() {
    let mut ram = Mem::new(RV_BASE, 8 * MIB);
    let e = life::prepare(&mut Bytes::new(b"not a kernel".to_vec()), &mut ram, &setup(Isa::Riscv64, 1, b""), &mut scratch()).unwrap_err();
    assert_eq!(e, PrepareError::Kernel(LoadError::Truncated));
    let e = life::prepare(&mut Bytes::new(vec![0; 4096]), &mut ram, &setup(Isa::Riscv64, 1, b""), &mut scratch()).unwrap_err();
    assert_eq!(e, PrepareError::Kernel(LoadError::NotElf));
    assert!(!e.reason().is_empty());
    let (_, file) = kernel_at(Isa::Aarch64, 0x4000_0000, 0);
    let mut ram = Mem::new(RV_BASE, 8 * MIB);
    let e = life::prepare(&mut Bytes::new(file), &mut ram, &setup(Isa::Riscv64, 1, b""), &mut scratch()).unwrap_err();
    assert_eq!(e, PrepareError::Kernel(LoadError::Machine));
    // Too many vCPUs for a tree.
    let (mut ram, file) = kernel_at(Isa::Riscv64, RV_BASE, 8 * MIB);
    let e = life::prepare(&mut Bytes::new(file), &mut ram, &setup(Isa::Riscv64, 17, b""), &mut scratch()).unwrap_err();
    assert_eq!(e, PrepareError::Tree(DtbError::BadConfig));
}

#[test]
fn a_scratch_too_small_for_the_description_is_an_error_and_the_kernel_still_loads_through_it() {
    let (mut ram, file) = kernel_at(Isa::Riscv64, RV_BASE, 8 * MIB);
    let r = life::prepare(&mut Bytes::new(file), &mut ram, &setup(Isa::Riscv64, 1, b""), &mut [0u8; 100]);
    assert_eq!(r, Err(PrepareError::Tree(DtbError::Full)));
    assert!(ram.get(RV_BASE + 0x20_0000, 0x3000) == &pattern(0x3000, 8)[..], "the kernel went through 100-byte chunks");
    let (mut ram, file) = kernel_at(Isa::X86_64, 0, 8 * MIB);
    let r = life::prepare(&mut Bytes::new(file), &mut ram, &setup(Isa::X86_64, 1, b""), &mut [0u8; 100]);
    assert_eq!(r, Err(PrepareError::Pvh(PvhError::Full)));
}

#[derive(Default)]
struct Recorder {
    started: Vec<(u64, u64)>,
}

impl Cpu for Recorder {
    fn launch(&mut self, pc: u64, arg: u64) -> Result<(), u32> {
        self.started.push((pc, arg));
        Ok(())
    }
    fn request_stop(&mut self) {}
    fn run_state(&mut self) -> Option<u64> {
        Some(life::RUN_RUNNING)
    }
}

#[test]
fn the_boot_cpu_starts_at_the_kernel_with_the_address_of_its_description() {
    for isa in [Isa::Riscv64, Isa::Aarch64, Isa::X86_64] {
        let (mut ram, file) = kernel_at(isa, if isa == Isa::Aarch64 { 0x4000_0000 } else { RV_BASE }, 32 * MIB);
        let entry = life::prepare(&mut Bytes::new(file), &mut ram, &setup(isa, 4, b""), &mut scratch()).unwrap();
        let mut cpus: Vec<Option<Recorder>> = (0..life::VCPUS).map(|k| (k < 4).then(Recorder::default)).collect();
        assert_eq!(life::boot(&mut cpus, 4, entry), Boot::Started);
        assert_eq!(cpus[0].as_ref().unwrap().started, [(entry.pc, entry.arg)], "{isa:?}");
        assert!(cpus[1..4].iter().all(|c| c.as_ref().unwrap().started.is_empty()), "{isa:?}: secondaries wait");
    }
}
