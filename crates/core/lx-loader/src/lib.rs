// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Relocatable-module loader for the Linux driver layer (RFC-0053 section 6).
//!
//! A Linux `.ko` is an ELF64 `ET_REL` object: sections, a symbol table and
//! `RELA` relocation tables, nothing linked. This crate turns one into code
//! and data a ring-3 server can run, in three pure steps:
//!
//! 1. [`Module::parse`] checks the header (ELF64, little-endian, `ET_REL`,
//!    riscv64 or aarch64) and every section header against the file length.
//! 2. [`Module::layout`] places every allocated section in one of two
//!    regions: **text** (`SHF_EXECINSTR`) and **data** (everything else,
//!    `.rodata` included). The server maps the two regions separately: data
//!    stays read-write and never executable; text is read-write only until
//!    the kernel flips it to read-execute (`SYS_MODULE_MAP_X`), never both.
//!    `.rodata` goes with data, not text: a constant pool that is executable
//!    is a gadget source, a writable one is merely writable.
//! 3. [`Module::load`] copies the bytes, resolves each undefined symbol
//!    through the caller's table and applies the relocations.
//!
//! **Scope by construction (RFC-0053 6.2).** Modules are compiled with
//! `-mcmodel=medany -mno-relax` (riscv64) or the small code model with
//! `-mgeneral-regs-only` (aarch64), `-fno-pic -fno-common`. That rules out a
//! GOT, a PLT, TLS, IFUNC and the dynamic-linking types; the loader refuses
//! each of them by name instead of mis-applying it. A branch that does not
//! reach its target (the region was placed too far from the server's text)
//! is refused, never truncated.
//!
//! **What the loader does not decide.** Whether these bytes may run at all is
//! the kernel's call: the server hands the *file* bytes to
//! `SYS_MODULE_VERIFY`, which checks them against the digest table built into
//! the kernel image, before any of this runs. [`admit`] adds the two checks a
//! Linux loader makes on `.modinfo`: a GPL-compatible licence tag and the
//! exact `vermagic` the server was built for.
//!
//! The crate allocates nothing and holds no state: every buffer is the
//! caller's, and every function is deterministic, so the host tests
//! (`tests/host/lx-loader-tests`) exercise exactly the code the server runs.

#![no_std]
#![deny(missing_docs)]

mod aarch64;
mod riscv64;

// ── ELF constants (System V gABI, and the two psABIs) ───────────────────────

const ET_REL: u16 = 1;
/// `e_machine` of RISC-V.
pub const EM_RISCV: u16 = 243;
/// `e_machine` of AArch64.
pub const EM_AARCH64: u16 = 183;

const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_RELA: u32 = 4;
const SHT_NOTE: u32 = 7;
const SHT_NOBITS: u32 = 8;
const SHT_REL: u32 = 9;
const SHT_INIT_ARRAY: u32 = 14;
const SHT_FINI_ARRAY: u32 = 15;
const SHT_PREINIT_ARRAY: u32 = 16;

const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;
const SHF_TLS: u64 = 0x400;

const SHN_UNDEF: u16 = 0;
const SHN_LORESERVE: u16 = 0xff00;
const SHN_ABS: u16 = 0xfff1;
const SHN_COMMON: u16 = 0xfff2;
const SHN_XINDEX: u16 = 0xffff;

const STB_LOCAL: u8 = 0;
const STT_TLS: u8 = 6;
const STT_GNU_IFUNC: u8 = 10;

const EHDR_LEN: usize = 64;
const SHDR_LEN: usize = 64;
const SYM_LEN: usize = 24;
const RELA_LEN: usize = 24;

/// The largest section alignment accepted. A module asks for page alignment
/// at most; anything larger is a malformed or hostile header, and honouring
/// it would let one section push the layout past any sane region.
pub const MAX_SECTION_ALIGN: u64 = 4096;

/// Sections that are read by the loader or the server and never placed.
/// `.modinfo` is the licence/vermagic record; `__versions` carries the
/// per-symbol CRCs `CONFIG_MODVERSIONS` adds (checked in L1, not mapped).
const UNPLACED: &[&[u8]] = &[b".modinfo", b"__versions"];

/// Section-name prefixes refused outright: runtime code patching
/// (`.altinstructions`, `.alternative`) needs a patcher the layer does not
/// have, and on these targets a Linux module only carries it for features
/// the server cannot provide.
const REFUSED_PREFIXES: &[&[u8]] = &[b".altinstr", b".alternative"];

// ── Errors ──────────────────────────────────────────────────────────────────

/// Why a module was refused. Every variant names what the caller would need
/// to report it; none is ever recovered from by guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error<'a> {
    /// Not an ELF64 little-endian file, or the header is cut short.
    NotElf64Le,
    /// An ELF file, but not `ET_REL` (a linked executable or a shared object).
    NotRelocatable,
    /// `e_machine` is neither riscv64 nor aarch64, or not the one expected.
    WrongMachine(u16),
    /// A header, table or string lies outside the file.
    Truncated,
    /// A section header's values are inconsistent (bad entry size, bad link,
    /// alignment not a power of two or above [`MAX_SECTION_ALIGN`]).
    BadSection(usize),
    /// No `SHT_SYMTAB` section, or more than one.
    NoSymtab,
    /// A section kind the loader refuses: TLS, `SHT_REL` on an allocated
    /// section, or a name in [`REFUSED_PREFIXES`].
    RefusedSection(&'a [u8]),
    /// A symbol kind the loader refuses (`STT_TLS`, `STT_GNU_IFUNC`,
    /// `SHN_COMMON`): the module was not built with the flags 6.2 requires.
    RefusedSymbol(&'a [u8]),
    /// An undefined symbol the caller's table does not provide.
    Unresolved(&'a [u8]),
    /// A relocation type outside the supported subset, on an allocated
    /// section. `(type, target section index)`.
    UnsupportedReloc(u32, usize),
    /// A relocation's result does not fit its field (a branch out of reach,
    /// a misaligned target, a 32-bit field overflowing). `(type, offset)`.
    Overflow(u32, u64),
    /// A relocation writes outside its section.
    RelocOutOfBounds(u32, u64),
    /// A `PCREL_LO12` relocation whose paired `PCREL_HI20` is not in the
    /// same table at the address its symbol names.
    MissingHi20(u64),
    /// The caller's text or data buffer is smaller than [`Layout`] asked for,
    /// or a base address is not aligned to the region's alignment.
    RegionTooSmall,
    /// The `.modinfo` licence tag is missing or not GPL-compatible.
    License(&'a [u8]),
    /// The `.modinfo` `vermagic` is missing or differs from the server's.
    Vermagic(&'a [u8]),
}

// ── Little-endian readers (bounds-checked) ──────────────────────────────────

fn rd_u16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}
fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off.checked_add(8)?)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

/// The ISA a module was built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isa {
    /// RV64 (`EM_RISCV`, ELFCLASS64).
    Riscv64,
    /// AArch64 (`EM_AARCH64`).
    Aarch64,
}

impl Isa {
    /// The ISA this crate was compiled for, if it is one of the two.
    pub const fn native() -> Option<Isa> {
        if cfg!(target_arch = "riscv64") {
            Some(Isa::Riscv64)
        } else if cfg!(target_arch = "aarch64") {
            Some(Isa::Aarch64)
        } else {
            None
        }
    }
}

/// One section header, decoded.
#[derive(Debug, Clone, Copy)]
pub struct Section {
    /// Offset of the name in the section-name string table.
    pub name_off: u32,
    /// `sh_type`.
    pub kind: u32,
    /// `sh_flags`.
    pub flags: u64,
    /// `sh_offset`.
    pub offset: u64,
    /// `sh_size`.
    pub size: u64,
    /// `sh_link`.
    pub link: u32,
    /// `sh_info`.
    pub info: u32,
    /// `sh_addralign` (0 and 1 both mean "no constraint").
    pub align: u64,
    /// `sh_entsize`.
    pub entsize: u64,
}

/// Which region a placed section lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Region {
    /// Executable once the kernel flips it; read-write until then.
    Text,
    /// Read-write, never executable.
    Data,
}

/// Sizes and alignments of the two regions a module needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Layout {
    /// Bytes of the text region.
    pub text_size: u64,
    /// Largest alignment of any text section (at least 1).
    pub text_align: u64,
    /// Bytes of the data region (`.bss` included).
    pub data_size: u64,
    /// Largest alignment of any data section (at least 1).
    pub data_align: u64,
}

/// A parsed, unloaded module: borrowed views into the object bytes.
#[derive(Debug, Clone, Copy)]
pub struct Module<'a> {
    obj: &'a [u8],
    isa: Isa,
    shoff: usize,
    shnum: usize,
    shstr: Section,
    symtab_index: usize,
    /// Which of the first 128 sections are placed in text / in data,
    /// classified once at parse time; `placement` is called for every
    /// relocation and used to re-classify every section each time (name
    /// lookups included), which made relocation quadratic in the section
    /// count. `classified` is false when a module has more than 128
    /// sections or one the loader refuses: then the original walk runs and
    /// reports the refusal as before.
    text_mask: u128,
    data_mask: u128,
    classified: bool,
    /// Offset of each classified section in its region (valid where a mask
    /// bit is set).
    offsets: [u32; 128],
    /// The symbol table and its string table, decoded once: every symbol
    /// lookup (one or two per relocation) used to re-read both headers.
    symtab_sec: Section,
    strtab_sec: Section,
    /// Indices of `__ksymtab` and `__ksymtab_gpl` (0: absent), found once.
    ksymtab: [u16; 2],
}

/// A decoded symbol.
#[derive(Debug, Clone, Copy)]
struct Sym {
    name: u32,
    info: u8,
    shndx: u16,
    value: u64,
}

impl<'a> Module<'a> {
    /// Parse and validate `obj`. With `expect = Some(isa)`, a module built
    /// for the other ISA is refused here rather than at its first relocation.
    pub fn parse(obj: &'a [u8], expect: Option<Isa>) -> Result<Self, Error<'a>> {
        if obj.len() < EHDR_LEN || &obj[0..4] != b"\x7fELF" || obj[4] != 2 || obj[5] != 1 {
            return Err(Error::NotElf64Le);
        }
        let e_type = rd_u16(obj, 16).ok_or(Error::Truncated)?;
        if e_type != ET_REL {
            return Err(Error::NotRelocatable);
        }
        let machine = rd_u16(obj, 18).ok_or(Error::Truncated)?;
        let isa = match machine {
            EM_RISCV => Isa::Riscv64,
            EM_AARCH64 => Isa::Aarch64,
            m => return Err(Error::WrongMachine(m)),
        };
        if let Some(want) = expect {
            if want != isa {
                return Err(Error::WrongMachine(machine));
            }
        }
        let shoff = rd_u64(obj, 40).ok_or(Error::Truncated)?;
        let shentsize = rd_u16(obj, 58).ok_or(Error::Truncated)? as usize;
        let shnum = rd_u16(obj, 60).ok_or(Error::Truncated)? as usize;
        let shstrndx = rd_u16(obj, 62).ok_or(Error::Truncated)? as usize;
        // Extended numbering (shnum == 0 or shstrndx == SHN_XINDEX) only
        // appears past 65 279 sections; no module has that many.
        if shentsize != SHDR_LEN || shnum == 0 || shstrndx >= shnum || shstrndx == SHN_XINDEX as usize {
            return Err(Error::BadSection(0));
        }
        let shoff = usize::try_from(shoff).map_err(|_| Error::Truncated)?;
        let table_end = shnum.checked_mul(SHDR_LEN).and_then(|n| n.checked_add(shoff)).ok_or(Error::Truncated)?;
        if table_end > obj.len() {
            return Err(Error::Truncated);
        }
        let mut m = Module {
            obj,
            isa,
            shoff,
            shnum,
            shstr: Section { name_off: 0, kind: 0, flags: 0, offset: 0, size: 0, link: 0, info: 0, align: 0, entsize: 0 },
            symtab_index: 0,
            text_mask: 0,
            data_mask: 0,
            classified: false,
            offsets: [0; 128],
            symtab_sec: Section { name_off: 0, kind: 0, flags: 0, offset: 0, size: 0, link: 0, info: 0, align: 0, entsize: 0 },
            strtab_sec: Section { name_off: 0, kind: 0, flags: 0, offset: 0, size: 0, link: 0, info: 0, align: 0, entsize: 0 },
            ksymtab: [0; 2],
        };
        // Every section's bytes (except NOBITS) must lie inside the file, and
        // its alignment must be sane, before anything trusts an offset.
        let mut symtabs = 0usize;
        for i in 0..shnum {
            let s = m.section(i)?;
            if s.kind != SHT_NOBITS && i != 0 {
                let end = s.offset.checked_add(s.size).ok_or(Error::BadSection(i))?;
                if end > obj.len() as u64 {
                    return Err(Error::Truncated);
                }
            }
            if s.align > MAX_SECTION_ALIGN || (s.align > 1 && !s.align.is_power_of_two()) {
                return Err(Error::BadSection(i));
            }
            if s.kind == SHT_SYMTAB {
                symtabs += 1;
                m.symtab_index = i;
                if s.entsize != SYM_LEN as u64 || s.size % SYM_LEN as u64 != 0 || s.link as usize >= shnum {
                    return Err(Error::BadSection(i));
                }
            }
            if s.kind == SHT_RELA
                && (s.entsize != RELA_LEN as u64 || s.size % RELA_LEN as u64 != 0
                    || s.link as usize >= shnum || s.info as usize >= shnum)
            {
                return Err(Error::BadSection(i));
            }
        }
        if symtabs != 1 {
            return Err(Error::NoSymtab);
        }
        m.shstr = m.section(shstrndx)?;
        m.symtab_sec = m.section(m.symtab_index)?;
        m.strtab_sec = m.section(m.symtab_sec.link as usize)?;
        for i in 1..shnum.min(u16::MAX as usize) {
            match m.section_name(i)? {
                b"__ksymtab" => m.ksymtab[0] = i as u16,
                b"__ksymtab_gpl" => m.ksymtab[1] = i as u16,
                _ => {}
            }
        }
        // Second pass now that the symbol table is known: every RELA must
        // name it (the first pass only checked the link is in range).
        for i in 0..shnum {
            let s = m.section(i)?;
            if s.kind == SHT_RELA && s.link as usize != m.symtab_index {
                return Err(Error::BadSection(i));
            }
        }
        if shnum <= 128 {
            let (mut text, mut data, mut ok) = (0u128, 0u128, true);
            let (mut tcur, mut dcur) = (0u64, 0u64);
            for i in 0..shnum {
                let r = match m.placement_kind(i) {
                    Ok(Some(r)) => r,
                    Ok(None) => continue,
                    Err(_) => {
                        ok = false;
                        break;
                    }
                };
                let sec = m.section(i)?;
                let a = sec.align.max(1);
                let cur = if r == Region::Text { &mut tcur } else { &mut dcur };
                let Some(at) = cur.checked_add(a - 1).map(|v| v & !(a - 1)) else { ok = false; break };
                let Some(end) = at.checked_add(sec.size) else { ok = false; break };
                let Ok(at32) = u32::try_from(at) else { ok = false; break };
                *cur = end;
                m.offsets[i] = at32;
                if r == Region::Text { text |= 1 << i } else { data |= 1 << i }
            }
            if ok {
                m.text_mask = text;
                m.data_mask = data;
                m.classified = true;
            }
        }
        Ok(m)
    }

    /// The ISA the module was built for.
    pub fn isa(&self) -> Isa {
        self.isa
    }

    /// Number of section headers.
    pub fn section_count(&self) -> usize {
        self.shnum
    }

    /// Section header `i`.
    pub fn section(&self, i: usize) -> Result<Section, Error<'a>> {
        if i >= self.shnum {
            return Err(Error::BadSection(i));
        }
        let o = self.shoff + i * SHDR_LEN;
        let b = self.obj;
        Ok(Section {
            name_off: rd_u32(b, o).ok_or(Error::Truncated)?,
            kind: rd_u32(b, o + 4).ok_or(Error::Truncated)?,
            flags: rd_u64(b, o + 8).ok_or(Error::Truncated)?,
            offset: rd_u64(b, o + 24).ok_or(Error::Truncated)?,
            size: rd_u64(b, o + 32).ok_or(Error::Truncated)?,
            link: rd_u32(b, o + 40).ok_or(Error::Truncated)?,
            info: rd_u32(b, o + 44).ok_or(Error::Truncated)?,
            align: rd_u64(b, o + 48).ok_or(Error::Truncated)?,
            entsize: rd_u64(b, o + 56).ok_or(Error::Truncated)?,
        })
    }

    /// A NUL-terminated string at `off` in the string-table section `strtab`.
    fn str_at(&self, strtab: &Section, off: u32) -> Result<&'a [u8], Error<'a>> {
        let start = strtab.offset.checked_add(off as u64).ok_or(Error::Truncated)? as usize;
        let end = (strtab.offset + strtab.size) as usize;
        if start >= end {
            return Err(Error::Truncated);
        }
        let s = &self.obj[start..end];
        let n = s.iter().position(|&c| c == 0).ok_or(Error::Truncated)?;
        Ok(&s[..n])
    }

    /// The name of section `i`.
    pub fn section_name(&self, i: usize) -> Result<&'a [u8], Error<'a>> {
        let s = self.section(i)?;
        self.str_at(&self.shstr, s.name_off)
    }

    /// The bytes of section `i` (empty for `SHT_NOBITS`).
    pub fn section_bytes(&self, i: usize) -> Result<&'a [u8], Error<'a>> {
        let s = self.section(i)?;
        if s.kind == SHT_NOBITS {
            return Ok(&[]);
        }
        Ok(&self.obj[s.offset as usize..(s.offset + s.size) as usize])
    }

    fn symtab(&self) -> Result<(Section, Section), Error<'a>> {
        Ok((self.symtab_sec, self.strtab_sec))
    }

    fn sym(&self, idx: usize) -> Result<Sym, Error<'a>> {
        let (st, _) = self.symtab()?;
        let count = (st.size / SYM_LEN as u64) as usize;
        if idx >= count {
            return Err(Error::Truncated);
        }
        let o = st.offset as usize + idx * SYM_LEN;
        let b = self.obj;
        Ok(Sym {
            name: rd_u32(b, o).ok_or(Error::Truncated)?,
            info: *b.get(o + 4).ok_or(Error::Truncated)?,
            shndx: rd_u16(b, o + 6).ok_or(Error::Truncated)?,
            value: rd_u64(b, o + 8).ok_or(Error::Truncated)?,
        })
    }

    fn sym_name(&self, s: &Sym) -> Result<&'a [u8], Error<'a>> {
        let (_, strs) = self.symtab()?;
        self.str_at(&strs, s.name)
    }

    /// Number of entries in the symbol table (index 0 is the null symbol).
    pub fn symbol_count(&self) -> usize {
        self.symtab().map_or(0, |(st, _)| (st.size / SYM_LEN as u64) as usize)
    }

    /// Calls `f(name)` for every undefined, non-local symbol: the module's
    /// imports, which the server's export table must provide. The count is
    /// the "undefined symbols" figure RFC-0053 tracks per module.
    pub fn for_each_import(&self, mut f: impl FnMut(&'a [u8])) -> Result<usize, Error<'a>> {
        let mut n = 0;
        for i in 1..self.symbol_count() {
            let s = self.sym(i)?;
            if s.shndx == SHN_UNDEF && (s.info >> 4) != STB_LOCAL {
                f(self.sym_name(&s)?);
                n += 1;
            }
        }
        Ok(n)
    }

    /// Value of `key` in `.modinfo` (`key=value` records, NUL-separated).
    pub fn modinfo(&self, key: &[u8]) -> Option<&'a [u8]> {
        for i in 0..self.shnum {
            if self.section_name(i).ok()? != b".modinfo" {
                continue;
            }
            for rec in self.section_bytes(i).ok()?.split(|&c| c == 0) {
                if rec.len() > key.len() && rec.starts_with(key) && rec[key.len()] == b'=' {
                    return Some(&rec[key.len() + 1..]);
                }
            }
        }
        None
    }

    /// Whether section `i` is placed, and in which region; `Ok(None)` for a
    /// section that is not loaded. Refuses the section kinds the loader does
    /// not support.
    fn placement_kind(&self, i: usize) -> Result<Option<Region>, Error<'a>> {
        let s = self.section(i)?;
        if i == 0 || s.flags & SHF_ALLOC == 0 {
            return Ok(None);
        }
        let name = self.section_name(i)?;
        if s.flags & SHF_TLS != 0 || REFUSED_PREFIXES.iter().any(|p| name.starts_with(p)) {
            return Err(Error::RefusedSection(name));
        }
        // Notes (`.note.gnu.build-id`, `.note.Linux`) are metadata Kbuild
        // marks allocated; no module code refers to them, so they are not
        // placed (Linux keeps them only for sysfs).
        if UNPLACED.contains(&name) || s.kind == SHT_NOTE {
            return Ok(None);
        }
        match s.kind {
            SHT_PROGBITS | SHT_NOBITS | SHT_INIT_ARRAY | SHT_FINI_ARRAY | SHT_PREINIT_ARRAY => {}
            // Any other allocated kind (`SHT_REL`, notes the server cannot
            // interpret as code or data) is refused, not silently dropped.
            _ => return Err(Error::RefusedSection(name)),
        }
        Ok(Some(if s.flags & SHF_EXECINSTR != 0 { Region::Text } else { Region::Data }))
    }

    /// Region and offset of section `i`, or `None` if it is not placed.
    /// Recomputed by walking the sections in order: deterministic, no table
    /// to allocate, and a module has a few dozen sections.
    pub fn placement(&self, i: usize) -> Result<Option<(Region, u64)>, Error<'a>> {
        if self.classified {
            if i >= self.shnum {
                return Ok(None);
            }
            let bit = 1u128 << i;
            let r = if self.text_mask & bit != 0 {
                Region::Text
            } else if self.data_mask & bit != 0 {
                Region::Data
            } else {
                return Ok(None);
            };
            return Ok(Some((r, self.offsets[i] as u64)));
        }
        let mut text = 0u64;
        let mut data = 0u64;
        for j in 0..self.shnum {
            let Some(r) = self.placement_kind(j)? else { continue };
            let s = self.section(j)?;
            let a = s.align.max(1);
            let cur = if r == Region::Text { &mut text } else { &mut data };
            let at = cur.checked_add(a - 1).ok_or(Error::BadSection(j))? & !(a - 1);
            if j == i {
                return Ok(Some((r, at)));
            }
            *cur = at.checked_add(s.size).ok_or(Error::BadSection(j))?;
        }
        Ok(None)
    }

    /// The two regions this module needs.
    pub fn layout(&self) -> Result<Layout, Error<'a>> {
        let mut l = Layout { text_size: 0, text_align: 1, data_size: 0, data_align: 1 };
        for j in 0..self.shnum {
            let Some(r) = self.placement_kind(j)? else { continue };
            let s = self.section(j)?;
            let a = s.align.max(1);
            let (size, align) = if r == Region::Text {
                (&mut l.text_size, &mut l.text_align)
            } else {
                (&mut l.data_size, &mut l.data_align)
            };
            let at = size.checked_add(a - 1).ok_or(Error::BadSection(j))? & !(a - 1);
            *size = at.checked_add(s.size).ok_or(Error::BadSection(j))?;
            *align = (*align).max(a);
        }
        Ok(l)
    }

    /// Copy, resolve and relocate into `text` (at run-time address
    /// `text_base`) and `data` (at `data_base`). Both buffers are zeroed
    /// first, so `.bss` and padding are zero. `resolve(name)` returns the
    /// run-time address of an import, or `None` (then the load fails with
    /// [`Error::Unresolved`]: an unresolved import is a build-time error in
    /// RFC-0053, never a run-time stub the loader invents).
    pub fn load(
        &self,
        text: &mut [u8],
        text_base: u64,
        data: &mut [u8],
        data_base: u64,
        resolve: &mut dyn FnMut(&[u8]) -> Option<u64>,
    ) -> Result<Loaded<'a>, Error<'a>> {
        let l = self.layout()?;
        if (text.len() as u64) < l.text_size || (data.len() as u64) < l.data_size
            || text_base % l.text_align != 0 || data_base % l.data_align != 0
        {
            return Err(Error::RegionTooSmall);
        }
        // Each import is resolved once: relocations name the same few
        // imports again and again, and the caller's lookup (an export table
        // walk) is the expensive part. Keyed by the name's address, which is
        // the same string-table entry for every reference to one symbol.
        let mut cache = [(0usize, 0u64); 64];
        let mut cached = 0usize;
        let outer = resolve;
        let resolve = &mut |n: &[u8]| -> Option<u64> {
            let key = n.as_ptr() as usize;
            if let Some(&(_, v)) = cache[..cached].iter().find(|(k, _)| *k == key) {
                return Some(v);
            }
            let v = outer(n)?;
            if cached < cache.len() {
                cache[cached] = (key, v);
                cached += 1;
            }
            Some(v)
        };
        let resolve: &mut dyn FnMut(&[u8]) -> Option<u64> = resolve;
        text.fill(0);
        data.fill(0);
        for i in 0..self.shnum {
            let Some((r, at)) = self.placement(i)? else { continue };
            let bytes = self.section_bytes(i)?;
            let dst = if r == Region::Text { &mut *text } else { &mut *data };
            dst[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
        }
        // Symbols are refused or resolved before any relocation is applied,
        // so a module with one bad import changes no byte of the regions
        // beyond the copy above.
        for i in 1..self.symbol_count() {
            let s = self.sym(i)?;
            let kind = s.info & 0xf;
            if kind == STT_TLS || kind == STT_GNU_IFUNC || s.shndx == SHN_COMMON {
                return Err(Error::RefusedSymbol(self.sym_name(&s)?));
            }
            if s.shndx == SHN_UNDEF && (s.info >> 4) != STB_LOCAL && resolve(self.sym_name(&s)?).is_none() {
                return Err(Error::Unresolved(self.sym_name(&s)?));
            }
        }
        let bases = Bases { text_base, data_base };
        for ri in 0..self.shnum {
            let rs = self.section(ri)?;
            if rs.kind == SHT_REL {
                // REL (implicit addend) is not what either psABI emits for
                // relocatable objects; refuse it on a placed target.
                if self.placement(rs.info as usize)?.is_some() {
                    return Err(Error::RefusedSection(self.section_name(ri)?));
                }
                continue;
            }
            if rs.kind != SHT_RELA {
                continue;
            }
            let target = rs.info as usize;
            let tgt = self.section(target)?;
            let placed = self.placement(target)?;
            let count = (rs.size / RELA_LEN as u64) as usize;
            for k in 0..count {
                let o = rs.offset as usize + k * RELA_LEN;
                let r_offset = rd_u64(self.obj, o).ok_or(Error::Truncated)?;
                let r_info = rd_u64(self.obj, o + 8).ok_or(Error::Truncated)?;
                let addend = rd_u64(self.obj, o + 16).ok_or(Error::Truncated)? as i64;
                let rtype = (r_info & 0xffff_ffff) as u32;
                let Some((region, sec_at)) = placed else {
                    // A table for a section that is not loaded (debug
                    // info): nothing to apply, but a type that is only
                    // legal in allocated sections is still checked.
                    self.check_unplaced_reloc(rtype, target)?;
                    continue;
                };
                let sym_idx = (r_info >> 32) as usize;
                let s_val = self.sym_value(sym_idx, &bases, resolve)?;
                let (buf, base) = if region == Region::Text { (&mut *text, text_base) } else { (&mut *data, data_base) };
                if r_offset >= tgt.size {
                    return Err(Error::RelocOutOfBounds(rtype, r_offset));
                }
                let site = (sec_at + r_offset) as usize;
                let p = base.wrapping_add(sec_at + r_offset);
                let mut ctx = RelocCtx { module: self, rela: &rs, bases: &bases, resolve: &mut *resolve };
                match self.isa {
                    Isa::Riscv64 => riscv64::apply(rtype, buf, site, p, s_val, addend, r_offset, &mut ctx, target)?,
                    Isa::Aarch64 => {
                        let _ = &mut ctx;
                        aarch64::apply(rtype, buf, site, p, s_val, addend, r_offset, target)?
                    }
                }
            }
        }
        Ok(Loaded { module: *self, bases })
    }

    fn check_unplaced_reloc(&self, rtype: u32, target: usize) -> Result<(), Error<'a>> {
        match self.isa {
            Isa::Riscv64 => riscv64::check_unplaced(rtype, target),
            Isa::Aarch64 => Ok(()),
        }
    }

    /// Run-time value of symbol `idx`: an import's resolved address, a
    /// placed section's address plus the symbol value, or an absolute.
    fn sym_value(&self, idx: usize, bases: &Bases, resolve: &mut dyn FnMut(&[u8]) -> Option<u64>) -> Result<u64, Error<'a>> {
        let s = self.sym(idx)?;
        if idx == 0 {
            return Ok(0);
        }
        match s.shndx {
            SHN_UNDEF => {
                let name = self.sym_name(&s)?;
                resolve(name).ok_or(Error::Unresolved(name))
            }
            SHN_ABS => Ok(s.value),
            SHN_COMMON => Err(Error::RefusedSymbol(self.sym_name(&s)?)),
            n if n >= SHN_LORESERVE => Err(Error::RefusedSymbol(self.sym_name(&s)?)),
            n => match self.placement(n as usize)? {
                Some((r, at)) => Ok(bases.of(r).wrapping_add(at).wrapping_add(s.value)),
                // A symbol in a section that is not loaded (e.g. `.modinfo`)
                // has no run-time address.
                None => Err(Error::RefusedSymbol(self.sym_name(&s)?)),
            },
        }
    }

    /// The section-relative value of symbol `idx` and its section, for the
    /// riscv64 `PCREL_LO12` pairing (the symbol names the `auipc`).
    fn sym_raw(&self, idx: usize) -> Result<(u16, u64), Error<'a>> {
        let s = self.sym(idx)?;
        Ok((s.shndx, s.value))
    }
}

/// Run-time bases of the two regions.
#[derive(Debug, Clone, Copy)]
struct Bases {
    text_base: u64,
    data_base: u64,
}

impl Bases {
    fn of(&self, r: Region) -> u64 {
        if r == Region::Text { self.text_base } else { self.data_base }
    }
}

/// What the ISA modules need from the loader to resolve a relocation that
/// refers to another relocation (riscv64 `PCREL_LO12_*`).
struct RelocCtx<'m, 'a, 'r> {
    module: &'m Module<'a>,
    rela: &'m Section,
    bases: &'m Bases,
    resolve: &'r mut dyn FnMut(&[u8]) -> Option<u64>,
}

/// A loaded module: symbol lookups against the run-time addresses.
#[derive(Debug, Clone, Copy)]
pub struct Loaded<'a> {
    module: Module<'a>,
    bases: Bases,
}

impl<'a> Loaded<'a> {
    /// Run-time address of the defined, non-local symbol `name`
    /// (a module's `init` entry point, for instance).
    pub fn symbol(&self, name: &[u8]) -> Option<u64> {
        let m = &self.module;
        for i in 1..m.symbol_count() {
            let s = m.sym(i).ok()?;
            if s.shndx == SHN_UNDEF || s.shndx >= SHN_LORESERVE || (s.info >> 4) == STB_LOCAL {
                continue;
            }
            if m.sym_name(&s).ok()? == name {
                let (r, at) = m.placement(s.shndx as usize).ok()??;
                return Some(self.bases.of(r).wrapping_add(at).wrapping_add(s.value));
            }
        }
        None
    }
}

impl<'a> Loaded<'a> {
    /// Calls `f(name, address)` for every symbol the module exports with
    /// `EXPORT_SYMBOL`/`EXPORT_SYMBOL_GPL`, read from its relocated
    /// `__ksymtab` (and `__ksymtab_gpl` when a tree still emits one) in
    /// `data`, the data region this module was loaded into. Only these are
    /// visible to a later module, exactly as for the Linux loader; a global
    /// that is not exported is not. Returns the count, or `None` for a
    /// malformed table.
    ///
    /// Entry shape (`struct kernel_symbol`, `include/linux/export-internal.h`):
    /// riscv64 has no `HAVE_ARCH_PREL32_RELOCATIONS`, so three absolute
    /// pointers (value, name, namespace; 24 bytes); aarch64 has it, so three
    /// `int` offsets from each field's own address (12 bytes).
    pub fn for_each_export(&self, data: &[u8], mut f: impl FnMut(&'_ [u8], u64)) -> Option<usize> {
        let m = &self.module;
        let stride: u64 = match m.isa() {
            Isa::Riscv64 => 24,
            Isa::Aarch64 => 12,
        };
        let db = self.bases.data_base;
        let mut count = 0;
        for i in m.ksymtab.iter().map(|&i| i as usize).filter(|&i| i != 0) {
            let s = m.section(i).ok()?;
            let (Region::Data, at) = m.placement(i).ok()?? else { return None };
            if s.size % stride != 0 {
                return None;
            }
            for e in 0..s.size / stride {
                let off = at.checked_add(e * stride)?;
                let o = usize::try_from(off).ok()?;
                let (value, name_at) = match m.isa() {
                    Isa::Riscv64 => (rd_u64(data, o)?, rd_u64(data, o + 8)?),
                    Isa::Aarch64 => {
                        let p = db.wrapping_add(off);
                        let rel = |k: usize| rd_u32(data, o + k).map(|v| v as i32 as i64 as u64);
                        (p.wrapping_add(rel(0)?), p.wrapping_add(4).wrapping_add(rel(4)?))
                    }
                };
                let start = usize::try_from(name_at.checked_sub(db)?).ok()?;
                let tail = data.get(start..)?;
                let len = tail.iter().position(|&b| b == 0)?;
                f(&tail[..len], value);
                count += 1;
            }
        }
        Some(count)
    }

    /// Run-time address of the exported symbol `name` (see
    /// [`Loaded::for_each_export`]).
    pub fn export(&self, data: &[u8], name: &[u8]) -> Option<u64> {
        let mut hit = None;
        self.for_each_export(data, |n, v| {
            if hit.is_none() && n == name {
                hit = Some(v);
            }
        })?;
        hit
    }
}

// ── Admission (.modinfo) ────────────────────────────────────────────────────

/// Licence tags accepted as GPL-compatible: the kernel's own list
/// (`license_is_gpl_compatible`: "GPL", "GPL v2", "GPL and additional
/// rights", "Dual BSD/GPL", "Dual MIT/GPL", "Dual MPL/GPL"), plus
/// "Dual Apache/GPL", the tag of this project's own modules (Apache-2.0 OR
/// GPL-2.0-only, so GPL-compatible by its GPL branch). "Proprietary" and
/// anything else are refused: the layer's exports stand in for
/// `EXPORT_SYMBOL_GPL`, and loading a proprietary module through them is what
/// Linux forbids (RFC-0053 6.3).
pub const GPL_COMPATIBLE: &[&[u8]] = &[
    b"GPL",
    b"GPL v2",
    b"GPL and additional rights",
    b"Dual BSD/GPL",
    b"Dual MIT/GPL",
    b"Dual MPL/GPL",
    b"Dual Apache/GPL",
];

/// Whether `tag` is in [`GPL_COMPATIBLE`] (exact match, as Linux does).
pub fn license_is_gpl_compatible(tag: &[u8]) -> bool {
    GPL_COMPATIBLE.contains(&tag)
}

/// The `.modinfo` checks a module must pass before it is laid out: a
/// GPL-compatible `license` and `vermagic` exactly equal to `vermagic`.
pub fn admit<'a>(m: &Module<'a>, vermagic: &[u8]) -> Result<(), Error<'a>> {
    match m.modinfo(b"license") {
        Some(l) if license_is_gpl_compatible(l) => {}
        Some(l) => return Err(Error::License(l)),
        None => return Err(Error::License(b"")),
    }
    match m.modinfo(b"vermagic") {
        Some(v) if v == vermagic => Ok(()),
        Some(v) => Err(Error::Vermagic(v)),
        None => Err(Error::Vermagic(b"")),
    }
}

// ── Shared field helpers ────────────────────────────────────────────────────

fn get32(buf: &[u8], at: usize, rtype: u32, off: u64) -> Result<u32, Error<'static>> {
    let s = buf.get(at..at + 4).ok_or(Error::RelocOutOfBounds(rtype, off))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn put32(buf: &mut [u8], at: usize, v: u32, rtype: u32, off: u64) -> Result<(), Error<'static>> {
    buf.get_mut(at..at + 4).ok_or(Error::RelocOutOfBounds(rtype, off))?.copy_from_slice(&v.to_le_bytes());
    Ok(())
}
fn get16(buf: &[u8], at: usize, rtype: u32, off: u64) -> Result<u16, Error<'static>> {
    let s = buf.get(at..at + 2).ok_or(Error::RelocOutOfBounds(rtype, off))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}
fn put16(buf: &mut [u8], at: usize, v: u16, rtype: u32, off: u64) -> Result<(), Error<'static>> {
    buf.get_mut(at..at + 2).ok_or(Error::RelocOutOfBounds(rtype, off))?.copy_from_slice(&v.to_le_bytes());
    Ok(())
}
fn get_n(buf: &[u8], at: usize, n: usize, rtype: u32, off: u64) -> Result<u64, Error<'static>> {
    let s = buf.get(at..at + n).ok_or(Error::RelocOutOfBounds(rtype, off))?;
    let mut a = [0u8; 8];
    a[..n].copy_from_slice(s);
    Ok(u64::from_le_bytes(a))
}
fn put_n(buf: &mut [u8], at: usize, n: usize, v: u64, rtype: u32, off: u64) -> Result<(), Error<'static>> {
    buf.get_mut(at..at + n).ok_or(Error::RelocOutOfBounds(rtype, off))?.copy_from_slice(&v.to_le_bytes()[..n]);
    Ok(())
}

/// Whether the signed value `v` fits in `bits` bits.
fn fits_signed(v: i64, bits: u32) -> bool {
    let lim = 1i64 << (bits - 1);
    v >= -lim && v < lim
}

/// Instruction-field encoders, public so the host tests can check them
/// against hand-assembled encodings independently of a whole module.
pub mod encode {
    pub use crate::aarch64::encode as aarch64;
    pub use crate::riscv64::encode as riscv64;
}
