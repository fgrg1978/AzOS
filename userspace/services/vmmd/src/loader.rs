// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Loading a guest kernel: an ELF64 executable read from a byte stream into
//! guest RAM at its load addresses.
//!
//! The volume's file calls have no offset (see `store`), so the file is read
//! once, front to back, and each chunk is offered to every window that wants
//! bytes of it: the `PT_LOAD` segments (copied to their physical address) and
//! the `PT_NOTE` segments (kept, to find the x86 PVH entry). A kernel
//! therefore loads whatever order its segments are in, and one that puts its
//! ELF header inside the first segment (the usual linker layout) still gets
//! those bytes, because the header and the program header table are replayed
//! through the same path once they are parsed.
//!
//! # What is checked, before a byte is written
//!
//! The kernel image is a file the guest owner supplied, not trusted code of
//! this task's: every segment must lie wholly inside guest RAM, no two may
//! overlap, the entry must lie inside a loaded segment, and the machine must
//! be the one this monitor runs (a guest enters the ISA of its host). A
//! refusal leaves RAM untouched.
//!
//! # Addresses
//!
//! Bytes go to `p_paddr`. The entry the caller gets is **physical**: the
//! kernels link high on some ISAs (`aarch64`: the entry symbol is a high
//! virtual address, the code is loaded low and enables its MMU itself), so
//! `e_entry` is translated through the segment that holds it. A guest starts
//! with its MMU off (or in a flat mode), so the physical address is the one
//! its first instruction has.

use crate::guest::GuestMem;

/// The ISA a guest runs: the one of the host (a guest enters the host's own
/// instruction set through the CPU's virtualization extension). The tests
/// give every value, the monitor [`HOST`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Isa {
    Riscv64,
    Aarch64,
    X86_64,
}

/// The ISA this program is built for.
pub const HOST: Isa = if cfg!(target_arch = "riscv64") {
    Isa::Riscv64
} else if cfg!(target_arch = "aarch64") {
    Isa::Aarch64
} else {
    Isa::X86_64
};

impl Isa {
    /// `e_machine` of the ISA.
    pub const fn machine(self) -> u16 {
        match self {
            Isa::Riscv64 => 243,
            Isa::Aarch64 => 183,
            Isa::X86_64 => 62,
        }
    }
}

/// Where the bytes of a kernel come from.
pub trait Source {
    /// Fill a prefix of `buf` from the next bytes. `Ok(0)` is the end of the
    /// file; `Err` a read that failed.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ()>;
}

/// A kernel in guest RAM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Image {
    /// Physical address of the first instruction. riscv64, aarch64:
    /// `e_entry` translated through the segment that holds it. x86_64: the
    /// kernel's 32-bit protected-mode entry, the PVH note
    /// (`XEN_ELFNOTE_PHYS32_ENTRY`), which must lie in a loaded segment.
    pub entry: u64,
    /// The lowest physical address a segment occupies.
    pub low: u64,
    /// One past the highest: the end of the image including its `.bss`.
    pub high: u64,
}

/// Why a kernel was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    /// A read failed.
    Read,
    /// The file ends before the header or a segment does.
    Truncated,
    /// Not an ELF64 little-endian executable (`ET_EXEC`).
    NotElf,
    /// Another machine than the host's.
    Machine,
    /// The program header table is not what a linker writes: it does not
    /// follow the ELF header, its entries are not 56 bytes, or it holds more
    /// than [`MAX_PHDRS`].
    Phdrs,
    /// More `PT_LOAD` segments than [`MAX_LOADS`], or none.
    Loads,
    /// A segment with more file bytes than memory, or whose range wraps.
    BadSegment,
    /// A segment (or the byte range it is read from) is not wholly inside guest RAM.
    OutOfRam,
    /// Two segments share physical addresses.
    Overlap,
    /// The entry lies in no loaded segment.
    BadEntry,
    /// An x86 kernel without a PVH entry note: it has no way to be started
    /// in 32-bit protected mode.
    NoPvhEntry,
}

/// Program headers read (a kernel has a handful).
pub const MAX_PHDRS: usize = 32;
/// `PT_LOAD` segments kept.
pub const MAX_LOADS: usize = 16;
/// Bytes of `PT_NOTE` segments kept to look for the PVH entry.
const NOTE_BYTES: usize = 256;

const EHDR: usize = 64;
const PHENT: usize = 56;
const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const ET_EXEC: u16 = 2;
/// `XEN_ELFNOTE_PHYS32_ENTRY`, owner "Xen".
const XEN_PHYS32_ENTRY: u32 = 18;

fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64le(b: &[u8], at: usize) -> u64 {
    let mut x = [0u8; 8];
    x.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(x)
}

/// A `PT_LOAD`: `filesz` bytes at file offset `off` go to `paddr`, up to
/// `memsz` bytes are zero.
#[derive(Clone, Copy, Default)]
struct Load {
    off: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
}

/// A `PT_NOTE`: `filesz` bytes at file offset `off`.
#[derive(Clone, Copy, Default)]
struct Note {
    off: u64,
    filesz: u64,
}

/// What [`parse_headers`] found.
struct Headers {
    entry: u64,
    loads: [Load; MAX_LOADS],
    nloads: usize,
    note: Note,
    /// How many bytes of the file the segments span: reading stops there.
    needed: u64,
}

fn parse_headers(hdr: &[u8], isa: Isa, ram: &dyn GuestMem) -> Result<Headers, LoadError> {
    if hdr[..4] != *b"\x7fELF" || hdr[4] != 2 || hdr[5] != 1 || u16le(hdr, 16) != ET_EXEC {
        return Err(LoadError::NotElf);
    }
    if u16le(hdr, 18) != isa.machine() {
        return Err(LoadError::Machine);
    }
    let entry = u64le(hdr, 24);
    let (phoff, phentsize, phnum) = (u64le(hdr, 32), u16le(hdr, 54) as usize, u16le(hdr, 56) as usize);
    if phoff != EHDR as u64 || phentsize != PHENT || phnum == 0 || phnum > MAX_PHDRS {
        return Err(LoadError::Phdrs);
    }
    let mut h = Headers {
        entry,
        loads: [Load::default(); MAX_LOADS],
        nloads: 0,
        note: Note::default(),
        needed: (EHDR + phnum * PHENT) as u64,
    };
    for i in 0..phnum {
        let p = &hdr[EHDR + i * PHENT..EHDR + (i + 1) * PHENT];
        let (kind, off, vaddr, paddr, filesz, memsz) =
            (u32le(p, 0), u64le(p, 8), u64le(p, 16), u64le(p, 24), u64le(p, 32), u64le(p, 40));
        match kind {
            PT_LOAD if memsz != 0 => {
                if h.nloads == MAX_LOADS {
                    return Err(LoadError::Loads);
                }
                if filesz > memsz || off.checked_add(filesz).is_none() || vaddr.checked_add(memsz).is_none() {
                    return Err(LoadError::BadSegment);
                }
                #[cfg(not(feature = "canary-elf-no-bounds"))]
                if !ram.contains(paddr, memsz) {
                    return Err(LoadError::OutOfRam);
                }
                h.needed = h.needed.max(off + filesz);
                h.loads[h.nloads] = Load { off, vaddr, paddr, filesz, memsz };
                h.nloads += 1;
            }
            PT_NOTE if h.note.filesz == 0 && filesz != 0 => {
                if off.checked_add(filesz).is_none() {
                    return Err(LoadError::BadSegment);
                }
                h.needed = h.needed.max(off + filesz.min(NOTE_BYTES as u64));
                h.note = Note { off, filesz };
            }
            _ => {}
        }
    }
    if h.nloads == 0 {
        return Err(LoadError::Loads);
    }
    let loads = &h.loads[..h.nloads];
    for (i, a) in loads.iter().enumerate() {
        for b in &loads[i + 1..] {
            if a.paddr < b.paddr + b.memsz && b.paddr < a.paddr + a.memsz {
                return Err(LoadError::Overlap);
            }
        }
    }
    Ok(h)
}

/// The physical address of virtual address `va`, through the segment that holds it.
fn translate(loads: &[Load], va: u64) -> Option<u64> {
    loads.iter().find(|l| va >= l.vaddr && va - l.vaddr < l.memsz).map(|l| l.paddr + (va - l.vaddr))
}

/// The part of `[start, start + len)` that overlaps `[win, win + wlen)`:
/// `(offset into the first range, offset into the window, bytes)`.
fn overlap(start: u64, len: u64, win: u64, wlen: u64) -> Option<(usize, u64, usize)> {
    let lo = start.max(win);
    let hi = (start + len).min(win.saturating_add(wlen));
    (lo < hi).then(|| ((lo - start) as usize, lo - win, (hi - lo) as usize))
}

/// Offer the file bytes `data`, which start at file offset `at`, to every window.
fn feed(
    h: &Headers,
    ram: &mut dyn GuestMem,
    notes: &mut [u8; NOTE_BYTES],
    at: u64,
    data: &[u8],
) -> Result<(), LoadError> {
    for l in &h.loads[..h.nloads] {
        if let Some((from, into, n)) = overlap(at, data.len() as u64, l.off, l.filesz) {
            ram.write(l.paddr + into, &data[from..from + n]).map_err(|_| LoadError::OutOfRam)?;
        }
    }
    if let Some((from, into, n)) = overlap(at, data.len() as u64, h.note.off, h.note.filesz.min(NOTE_BYTES as u64)) {
        notes[into as usize..into as usize + n].copy_from_slice(&data[from..from + n]);
    }
    Ok(())
}

/// Zero `[from, to)` of guest RAM: the part of a segment past its file
/// bytes, written from `zeros`, which is all zero.
fn zero(ram: &mut dyn GuestMem, mut from: u64, to: u64, zeros: &[u8]) -> Result<(), LoadError> {
    while from < to && !zeros.is_empty() {
        let n = (to - from).min(zeros.len() as u64) as usize;
        ram.write(from, &zeros[..n]).map_err(|_| LoadError::OutOfRam)?;
        from += n as u64;
    }
    Ok(())
}

/// The `XEN_ELFNOTE_PHYS32_ENTRY` among the notes in `b`, if any.
fn pvh_entry(b: &[u8]) -> Option<u32> {
    let mut at = 0usize;
    while at + 12 <= b.len() {
        let (namesz, descsz, kind) = (u32le(b, at) as usize, u32le(b, at + 4) as usize, u32le(b, at + 8));
        let name = at + 12;
        let desc = name + namesz.next_multiple_of(4);
        let next = desc.checked_add(descsz.next_multiple_of(4))?;
        if next > b.len() {
            return None;
        }
        if kind == XEN_PHYS32_ENTRY && descsz >= 4 && b[name..name + namesz] == *b"Xen\0" {
            return Some(u32le(b, desc));
        }
        at = next;
    }
    None
}

fn read_full(src: &mut dyn Source, buf: &mut [u8]) -> Result<(), LoadError> {
    let mut done = 0;
    while done < buf.len() {
        match src.read(&mut buf[done..]) {
            Ok(0) => return Err(LoadError::Truncated),
            Ok(n) => done += n,
            Err(()) => return Err(LoadError::Read),
        }
    }
    Ok(())
}

/// Read the kernel from `src` and place it in `ram`. `buf` is the chunk the
/// file is read through (a task has a small stack, so the caller lends the
/// buffer); its contents are not kept.
pub fn load(src: &mut dyn Source, ram: &mut dyn GuestMem, isa: Isa, buf: &mut [u8]) -> Result<Image, LoadError> {
    let mut hdr = [0u8; EHDR + MAX_PHDRS * PHENT];
    read_full(src, &mut hdr[..EHDR])?;
    if hdr[..4] != *b"\x7fELF" {
        return Err(LoadError::NotElf);
    }
    // The table's size is the header's to say; the rest is checked once read.
    let phnum = u16le(&hdr, 56) as usize;
    if phnum == 0 || phnum > MAX_PHDRS {
        return Err(LoadError::Phdrs);
    }
    let table = EHDR + phnum * PHENT;
    read_full(src, &mut hdr[EHDR..table])?;
    let h = parse_headers(&hdr[..table], isa, ram)?;

    // The bytes already read are part of whichever segment holds them.
    let mut notes = [0u8; NOTE_BYTES];
    feed(&h, ram, &mut notes, 0, &hdr[..table])?;
    let mut at = table as u64;
    while at < h.needed {
        let want = ((h.needed - at) as usize).min(buf.len());
        match src.read(&mut buf[..want]) {
            Ok(0) => return Err(LoadError::Truncated),
            Ok(n) => {
                feed(&h, ram, &mut notes, at, &buf[..n])?;
                at += n as u64;
            }
            Err(()) => return Err(LoadError::Read),
        }
    }
    let loads = &h.loads[..h.nloads];
    buf.fill(0);
    for l in loads {
        zero(ram, l.paddr + l.filesz, l.paddr + l.memsz, buf)?;
    }

    let entry = if isa == Isa::X86_64 {
        let pvh = pvh_entry(&notes[..(h.note.filesz as usize).min(NOTE_BYTES)]).ok_or(LoadError::NoPvhEntry)?;
        let pa = pvh as u64;
        loads.iter().any(|l| pa >= l.paddr && pa - l.paddr < l.memsz).then_some(pa).ok_or(LoadError::BadEntry)?
    } else {
        translate(loads, h.entry).ok_or(LoadError::BadEntry)?
    };
    Ok(Image {
        entry,
        low: loads.iter().map(|l| l.paddr).min().unwrap_or(0),
        high: loads.iter().map(|l| l.paddr + l.memsz).max().unwrap_or(0),
    })
}
