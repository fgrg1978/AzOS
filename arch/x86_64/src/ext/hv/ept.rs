// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Intel extended page tables: the guest-physical to host-physical map of the
//! VMX backend, the counterpart of [`super::npt`].
//!
//! An EPT entry is **not** an x86 page-table entry. What `npt.rs` takes from
//! the kernel's PTE builder (`crate::mmu`) is wrong here, field by field:
//!
//! | bit | x86 PTE | EPT entry |
//! |-----|---------|-----------|
//! | 0 | present | **read** |
//! | 1 | writable | **write** |
//! | 2 | user | **execute** |
//! | 5:3 | accessed, dirty, ... | memory type (leaf only) |
//! | 6 | dirty | ignore-PAT (leaf only) |
//! | 7 | page size | large page (levels 1 and 2) |
//! | 8 / 9 | global / ... | accessed / dirty, only when the EPTP enables them |
//! | 63 | no-execute | suppress #VE |
//!
//! "Present" is therefore *any of read, write, execute*, and a table pointer
//! is read+write+execute. This module builds and walks entries in that format
//! with the same [`TableMem`] the kernel's walkers use.
//!
//! One property is relied on elsewhere and pinned by a host test: every entry
//! this module writes has bit 0 (read) set and bit 7 clear on a table pointer,
//! so the format-agnostic part of the guest-memory walk in
//! [`super::vcpu`] (`mmu::translate`, which reads "present" from bit 0, the
//! page-size bit from bit 7 and the address from bits 12..51) walks an EPT
//! tree to the same leaf as [`translate`] does. Execute-only pages (which
//! EPT can express and x86 paging cannot) are never built.
//!
//! The tables are always 4 levels (a 48-bit guest-physical space; the
//! hypervisor's `gpa_bits` stays 47 as for NPT, the walks above it being
//! canonical-address walks). Mappings are 4 KiB: the monitor maps frames of
//! memory objects one page at a time.

use crate::mmu::{TableMem, WalkError};

use super::mmio::GuestMem;
use super::npt::GuestAccess;

/// Entry bit: read.
pub const READ: u64 = 1 << 0;
/// Entry bit: write.
pub const WRITE: u64 = 1 << 1;
/// Entry bit: execute (supervisor execute when mode-based execute control is off).
pub const EXEC: u64 = 1 << 2;
/// The three permission bits.
pub const RWX: u64 = READ | WRITE | EXEC;
/// Leaf: the memory-type field starts here.
pub const MT_SHIFT: u32 = 3;
/// Memory type write-back.
pub const MT_WB: u64 = 6;
/// Leaf: ignore the guest's PAT (the EPT memory type is final).
pub const IGNORE_PAT: u64 = 1 << 6;
/// Levels 1 and 2: this entry maps a 2 MiB / 1 GiB page.
pub const LARGE: u64 = 1 << 7;
/// Accessed flag (when the EPTP asks for it).
pub const ACCESSED: u64 = 1 << 8;
/// Dirty flag (when the EPTP asks for it).
pub const DIRTY: u64 = 1 << 9;
/// Physical address bits of an entry.
pub const ADDR_MASK: u64 = ((1u64 << 52) - 1) & !0xFFF;

/// Levels of every tree built here: PML4, PDPT, PD, PT.
pub const LEVELS: usize = 4;
/// Bits of guest-physical address a 4-level walk covers.
pub const GPA_BITS: u32 = 48;

const ENTRIES: usize = 512;
const PAGE: usize = 4096;

/// `EPTP` bits 2:0: the memory type of the paging structures (write-back).
const EPTP_MT_WB: u64 = 6;
/// `EPTP` bits 5:3: page-walk length minus one.
const EPTP_WALK_4: u64 = ((LEVELS as u64) - 1) << 3;
/// `EPTP` bit 6: accessed and dirty flags enabled.
const EPTP_AD: u64 = 1 << 6;

/// The `EPT_POINTER` VMCS field for a tree rooted at physical `root`.
/// `ad`: let the CPU set accessed/dirty flags (capability `EPT_VPID_CAP[21]`);
/// the monitor does not read them, so the VMX entry leaves it off.
pub const fn eptp(root: u64, ad: bool) -> u64 {
    (root & ADDR_MASK) | EPTP_MT_WB | EPTP_WALK_4 | if ad { EPTP_AD } else { 0 }
}

/// The tree root an `EPTP` names.
pub const fn eptp_root(eptp: u64) -> u64 {
    eptp & ADDR_MASK
}

/// Does `word` map or point to anything? (Any of read, write, execute.)
pub const fn present(word: u64) -> bool {
    word & RWX != 0
}

/// A pointer to the next-level table at `pa`: read, write, execute.
pub const fn table_entry(pa: u64) -> u64 {
    (pa & ADDR_MASK) | RWX
}

/// A 4 KiB leaf to `hpa`: read always, write and execute as asked, write-back,
/// the guest's PAT applies (`IGNORE_PAT` clear), so a guest that programs a
/// page as uncached (a device window it maps itself) gets it.
pub const fn leaf_entry(hpa: u64, a: GuestAccess) -> u64 {
    (hpa & ADDR_MASK)
        | READ
        | if a.write { WRITE } else { 0 }
        | if a.exec { EXEC } else { 0 }
        | MT_WB << MT_SHIFT
}

/// What a leaf lets the guest do.
pub const fn access_of(word: u64) -> GuestAccess {
    GuestAccess { write: word & WRITE != 0, exec: word & EXEC != 0 }
}

/// A pointer to a lower table when read at `level` (levels above 0 only).
const fn is_table(word: u64, level: usize) -> bool {
    level > 0 && present(word) && word & LARGE == 0
}

/// The index into the table at `level` that `gpa` selects.
const fn index(gpa: usize, level: usize) -> usize {
    (gpa >> (12 + 9 * level)) & (ENTRIES - 1)
}

/// Bytes a leaf at `level` covers.
const fn span(level: usize) -> usize {
    PAGE << (9 * level)
}

/// A leaf found by [`translate`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Leaf {
    /// The entry.
    pub word: u64,
    /// 0 = 4 KiB, 1 = 2 MiB, 2 = 1 GiB.
    pub level: usize,
    /// The host-physical address `gpa` translates to.
    pub phys: u64,
}

/// Map guest-physical `gpa` to host-physical `hpa` with a 4 KiB leaf,
/// allocating intermediate tables from `mem`. The caller invalidates the
/// guest's TLB (`INVEPT`) before the next entry when this replaced a mapping;
/// a new mapping needs nothing.
pub fn map<M: TableMem>(mem: &mut M, root: usize, gpa: usize, hpa: usize, a: GuestAccess) -> Result<(), WalkError> {
    if gpa >> GPA_BITS != 0 {
        return Err(WalkError::NotCanonical);
    }
    if gpa & (PAGE - 1) != 0 || hpa & (PAGE - 1) != 0 || hpa as u64 & !ADDR_MASK != 0 {
        return Err(WalkError::Misaligned);
    }
    let mut table = root;
    for level in (1..LEVELS).rev() {
        let idx = index(gpa, level);
        let w = mem.read(table, idx);
        if is_table(w, level) {
            table = (w & ADDR_MASK) as usize;
        } else if present(w) {
            // A 2 MiB or 1 GiB leaf already covers it.
            return Err(WalkError::HugeLeafInTheWay);
        } else {
            let next = mem.alloc_table().ok_or(WalkError::NoMemory)?;
            mem.write(table, idx, table_entry(next as u64));
            table = next;
        }
    }
    let idx = index(gpa, 0);
    if present(mem.read(table, idx)) {
        return Err(WalkError::AlreadyMapped);
    }
    mem.write(table, idx, leaf_entry(hpa as u64, a));
    Ok(())
}

/// The leaf translating `gpa`, whatever its size, if any.
pub fn translate<M: TableMem>(mem: &M, root: usize, gpa: usize) -> Option<Leaf> {
    if gpa >> GPA_BITS != 0 {
        return None;
    }
    let mut table = root;
    for level in (0..LEVELS).rev() {
        let w = mem.read(table, index(gpa, level));
        if !present(w) {
            return None;
        }
        if level == 0 || w & LARGE != 0 {
            let phys = (w & ADDR_MASK) + (gpa & (span(level) - 1)) as u64;
            return Some(Leaf { word: w, level, phys });
        }
        table = (w & ADDR_MASK) as usize;
    }
    None
}

/// Remove the 4 KiB leaf translating `gpa` and return the host frame it
/// named. The caller shoots the TLB down (`INVEPT`) before freeing the frame.
/// A larger leaf covering `gpa` is [`WalkError::HugeLeafInTheWay`]: part of it
/// is not a 4 KiB unmap.
pub fn unmap<M: TableMem>(mem: &mut M, root: usize, gpa: usize) -> Result<u64, WalkError> {
    if gpa >> GPA_BITS != 0 {
        return Err(WalkError::NotCanonical);
    }
    let mut table = root;
    for level in (0..LEVELS).rev() {
        let idx = index(gpa, level);
        let w = mem.read(table, idx);
        if !present(w) {
            return Err(WalkError::NotMapped);
        }
        if level == 0 {
            mem.write(table, idx, 0);
            return Ok(w & ADDR_MASK);
        }
        if w & LARGE != 0 {
            return Err(WalkError::HugeLeafInTheWay);
        }
        table = (w & ADDR_MASK) as usize;
    }
    Err(WalkError::NotMapped)
}

/// Host-physical reads for a walk of guest tables: the words of a tree, the
/// guest's bytes.
pub type ReadPhys<'a> = &'a dyn Fn(u64, &mut [u8]) -> bool;

/// A tree read through `read_phys`.
struct Walk<'a>(ReadPhys<'a>);

impl TableMem for Walk<'_> {
    fn read(&self, table: usize, idx: usize) -> u64 {
        let mut b = [0u8; 8];
        if (self.0)(table as u64 + idx as u64 * 8, &mut b) { u64::from_le_bytes(b) } else { 0 }
    }
    fn write(&mut self, _table: usize, _idx: usize, _word: u64) {}
    fn alloc_table(&mut self) -> Option<usize> {
        None
    }
}

/// Guest RAM as the tree rooted at `root` maps it: what the service reads the
/// bytes of an instruction through ([`super::mmio`]).
pub struct GuestRam<'a> {
    pub root: u64,
    pub read_phys: ReadPhys<'a>,
}

impl GuestMem for GuestRam<'_> {
    fn read(&self, gpa: u64, buf: &mut [u8]) -> bool {
        let walk = Walk(self.read_phys);
        let mut done = 0;
        while done < buf.len() {
            let at = gpa + done as u64;
            let Some(l) = translate(&walk, self.root as usize, at as usize) else { return false };
            let n = (PAGE - (at as usize & (PAGE - 1))).min(buf.len() - done);
            if !(self.read_phys)(l.phys, &mut buf[done..done + n]) {
                return false;
            }
            done += n;
        }
        true
    }
}
