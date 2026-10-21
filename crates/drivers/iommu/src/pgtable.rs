// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The I/O page tables the four IOMMUs walk, and the radix tree that builds
//! them.
//!
//! All four use 4 KiB tables of 512 eight-byte entries and 9 index bits per
//! level; they differ in what an entry looks like:
//!
//! | kind | table entry | leaf entry | present |
//! |---|---|---|---|
//! | RISC-V Sv39/Sv48 (IOSATP) | `PPN<<10 \| V` | `PPN<<10 \| V R [W] U A D` | V |
//! | Arm LPAE stage 1, 4 KiB granule | `addr \| 0b11` | `addr \| 0b11 \| attrs` (level 3) | bit 0 |
//! | Intel VT-d second level | `addr \| R W` | `addr \| R [W]` | R or W |
//! | AMD-Vi v1 | `addr \| PR \| NextLevel<<9 \| IR IW` | `addr \| PR \| IR [IW]` | PR |
//!
//! Only 4 KiB leaves are built; no superpages (a device buffer is a few
//! pages, and a superpage would let a device reach its neighbours).
//!
//! A write-only mapping is not expressible on RISC-V (W without R is a
//! reserved PTE encoding) nor on Arm stage 1 (writable implies readable),
//! so a request for write-only is granted read-write there; the other two
//! express it exactly. [`Perm`] is a floor, never a ceiling.

use crate::{rd64, wr64, TableMem};
use azos_dma::Direction;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PtKind {
    RiscvSv,
    ArmLpae,
    Vtd,
    AmdVi,
}

/// A page-table format and the number of levels the root has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PtFormat {
    pub kind: PtKind,
    pub levels: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Perm {
    pub read: bool,
    pub write: bool,
}

impl Perm {
    pub const NONE: Perm = Perm { read: false, write: false };
    pub const RW: Perm = Perm { read: true, write: true };

    /// What the device needs for a transfer of direction `dir`: it READS the
    /// buffer for `ToDevice` and WRITES it for `FromDevice`.
    pub const fn of(dir: Direction) -> Perm {
        match dir {
            Direction::ToDevice => Perm { read: true, write: false },
            Direction::FromDevice => Perm { read: false, write: true },
            Direction::Bidirectional => Perm::RW,
        }
    }

    pub const fn union(self, o: Perm) -> Perm {
        Perm { read: self.read || o.read, write: self.write || o.write }
    }

    pub const fn is_none(self) -> bool {
        !self.read && !self.write
    }
}

// RISC-V PTE bits (privileged spec 4.3.1; the IOMMU spec reuses them).
const RV_V: u64 = 1 << 0;
const RV_R: u64 = 1 << 1;
const RV_W: u64 = 1 << 2;
const RV_X: u64 = 1 << 3;
const RV_U: u64 = 1 << 4;
const RV_A: u64 = 1 << 6;
const RV_D: u64 = 1 << 7;
const RV_PPN_SHIFT: u32 = 10;
const RV_PPN_MASK: u64 = (1 << 44) - 1;

// Arm VMSAv8-64 stage 1 descriptor bits (4 KiB granule).
const ARM_VALID: u64 = 1 << 0;
const ARM_TABLE_OR_PAGE: u64 = 1 << 1;
const ARM_ATTRIDX0: u64 = 0 << 2;
const ARM_AP_EL0: u64 = 1 << 6; // AP[1]: accessible to unprivileged transactions
const ARM_AP_RO: u64 = 1 << 7; // AP[2]: read only
const ARM_SH_INNER: u64 = 3 << 8;
const ARM_AF: u64 = 1 << 10;
const ARM_NG: u64 = 1 << 11;
const ARM_PXN: u64 = 1 << 53;
const ARM_UXN: u64 = 1 << 54;
const ARM_ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;

// Intel VT-d second-level entry bits (VT-d spec 9.8).
const VTD_R: u64 = 1 << 0;
const VTD_W: u64 = 1 << 1;
const VTD_SP: u64 = 1 << 7;
const VTD_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

// AMD-Vi I/O page table entry bits (AMD IOMMU spec 2.2.3).
const AMD_PR: u64 = 1 << 0;
const AMD_NL_SHIFT: u32 = 9;
const AMD_NL_MASK: u64 = 7 << 9;
const AMD_IR: u64 = 1 << 61;
const AMD_IW: u64 = 1 << 62;
const AMD_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

impl PtFormat {
    pub const fn new(kind: PtKind, levels: u8) -> Self {
        PtFormat { kind, levels }
    }

    /// Does the kind support this many levels?
    pub const fn is_valid(&self) -> bool {
        match self.kind {
            PtKind::RiscvSv | PtKind::ArmLpae | PtKind::Vtd => self.levels == 3 || self.levels == 4,
            PtKind::AmdVi => self.levels >= 3 && self.levels <= 6,
        }
    }

    /// Is `iova` inside the input range the root covers?
    pub const fn contains(&self, iova: u64) -> bool {
        let bits = 12 + 9 * self.levels as u32;
        match self.kind {
            // Sv39/Sv48 take sign-extended addresses; only the positive half
            // is used here.
            PtKind::RiscvSv => iova < (1u64 << (bits - 1)),
            PtKind::ArmLpae | PtKind::Vtd => iova < (1u64 << bits),
            PtKind::AmdVi => bits >= 64 || iova < (1u64 << bits),
        }
    }

    /// The entry that links a table of level `child_level` (0 = leaf table)
    /// at physical address `child_pa`.
    pub const fn table_entry(&self, child_pa: u64, child_level: u8) -> u64 {
        match self.kind {
            PtKind::RiscvSv => (((child_pa >> 12) & RV_PPN_MASK) << RV_PPN_SHIFT) | RV_V,
            PtKind::ArmLpae => (child_pa & ARM_ADDR_MASK) | ARM_TABLE_OR_PAGE | ARM_VALID,
            PtKind::Vtd => (child_pa & VTD_ADDR_MASK) | VTD_R | VTD_W,
            // NextLevel names the AMD level of the child, which counts from
            // 1 at the leaf table.
            PtKind::AmdVi => {
                (child_pa & AMD_ADDR_MASK) | ((child_level as u64 + 1) << AMD_NL_SHIFT) | AMD_IR | AMD_IW | AMD_PR
            }
        }
    }

    /// The entry that maps one 4 KiB page at `pa` with `perm`.
    pub const fn leaf_entry(&self, pa: u64, perm: Perm) -> u64 {
        let write = perm.write;
        match self.kind {
            PtKind::RiscvSv => {
                // The IOMMU treats a request without a process id as
                // user-mode (U must be set), and with SADE off faults on a
                // clear A (and a clear D for a write): set both up front.
                let rw = if write { RV_R | RV_W } else { RV_R };
                (((pa >> 12) & RV_PPN_MASK) << RV_PPN_SHIFT) | rw | RV_U | RV_A | RV_D | RV_V
            }
            PtKind::ArmLpae => {
                let ap = if write { ARM_AP_EL0 } else { ARM_AP_EL0 | ARM_AP_RO };
                (pa & ARM_ADDR_MASK)
                    | ARM_TABLE_OR_PAGE
                    | ARM_VALID
                    | ARM_ATTRIDX0
                    | ap
                    | ARM_SH_INNER
                    | ARM_AF
                    | ARM_NG
                    | ARM_PXN
                    | ARM_UXN
            }
            PtKind::Vtd => {
                (pa & VTD_ADDR_MASK) | if perm.read { VTD_R } else { 0 } | if write { VTD_W } else { 0 }
            }
            PtKind::AmdVi => {
                (pa & AMD_ADDR_MASK) | AMD_PR | if perm.read { AMD_IR } else { 0 } | if write { AMD_IW } else { 0 }
            }
        }
    }

    /// Does the entry map anything (or link a table)?
    pub const fn is_present(&self, e: u64) -> bool {
        match self.kind {
            PtKind::RiscvSv => e & RV_V != 0,
            PtKind::ArmLpae => e & ARM_VALID != 0,
            PtKind::Vtd => e & (VTD_R | VTD_W) != 0,
            PtKind::AmdVi => e & AMD_PR != 0,
        }
    }

    /// Is a present entry in an UPPER table a leaf (a superpage this crate
    /// never builds)? Walking into one is a corrupt table.
    pub const fn is_upper_leaf(&self, e: u64) -> bool {
        match self.kind {
            PtKind::RiscvSv => e & (RV_R | RV_W | RV_X) != 0,
            PtKind::ArmLpae => e & ARM_TABLE_OR_PAGE == 0,
            PtKind::Vtd => e & VTD_SP != 0,
            PtKind::AmdVi => {
                let nl = (e & AMD_NL_MASK) >> AMD_NL_SHIFT;
                nl == 0 || nl == 7
            }
        }
    }

    /// The physical address an entry points at.
    pub const fn entry_pa(&self, e: u64) -> u64 {
        match self.kind {
            PtKind::RiscvSv => ((e >> RV_PPN_SHIFT) & RV_PPN_MASK) << 12,
            PtKind::ArmLpae => e & ARM_ADDR_MASK,
            PtKind::Vtd => e & VTD_ADDR_MASK,
            PtKind::AmdVi => e & AMD_ADDR_MASK,
        }
    }

    /// What a present leaf permits.
    pub const fn leaf_perm(&self, e: u64) -> Perm {
        match self.kind {
            PtKind::RiscvSv => Perm { read: e & RV_R != 0, write: e & RV_W != 0 },
            PtKind::ArmLpae => Perm { read: true, write: e & ARM_AP_RO == 0 },
            PtKind::Vtd => Perm { read: e & VTD_R != 0, write: e & VTD_W != 0 },
            PtKind::AmdVi => Perm { read: e & AMD_IR != 0, write: e & AMD_IW != 0 },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PtError {
    NoMemory,
    /// `iova` is outside what the root's levels cover, or the format is invalid.
    OutOfRange,
    /// A table holds an entry this crate would never have written.
    Corrupt,
}

/// A radix tree of 4 KiB tables in the format of a unit. The tables live in
/// `TableMem` pages; this value is just the root and the format.
#[derive(Debug)]
pub struct IoPageTable {
    fmt: PtFormat,
    root: u64,
}

const fn index(level: u8, iova: u64) -> usize {
    ((iova >> (12 + 9 * level as u32)) & 0x1ff) as usize
}

impl IoPageTable {
    pub fn new(fmt: PtFormat, mem: &dyn TableMem) -> Result<Self, PtError> {
        if !fmt.is_valid() {
            return Err(PtError::OutOfRange);
        }
        let root = mem.alloc_page().ok_or(PtError::NoMemory)?;
        Ok(IoPageTable { fmt, root })
    }

    pub fn format(&self) -> PtFormat {
        self.fmt
    }

    pub fn root_pa(&self) -> u64 {
        self.root
    }

    fn set(&self, mem: &dyn TableMem, table: u64, idx: usize, val: u64) {
        wr64(mem, table, idx, val);
        mem.clean(table + (idx as u64) * 8, 8);
    }

    /// Map the page at `iova` to `pa` with `perm`, replacing what was there.
    /// Returns whether the leaf changed (a unit may hold the old translation,
    /// or, in caching mode, a cached "not present" for a page that is mapped
    /// now: the caller flushes either way); writing the entry that is already
    /// there changes nothing and returns false.
    pub fn map_page(&mut self, mem: &dyn TableMem, iova: u64, pa: u64, perm: Perm) -> Result<bool, PtError> {
        if !self.fmt.contains(iova) {
            return Err(PtError::OutOfRange);
        }
        let mut table = self.root;
        for level in (1..self.fmt.levels).rev() {
            let idx = index(level, iova);
            let e = rd64(mem, table, idx);
            if self.fmt.is_present(e) {
                if self.fmt.is_upper_leaf(e) {
                    return Err(PtError::Corrupt);
                }
                table = self.fmt.entry_pa(e);
            } else {
                let child = mem.alloc_page().ok_or(PtError::NoMemory)?;
                // The child is empty (zeroed); link it last so a walker
                // never sees a half-built table.
                self.set(mem, table, idx, self.fmt.table_entry(child, level - 1));
                table = child;
            }
        }
        let idx = index(0, iova);
        let old = rd64(mem, table, idx);
        let new = self.fmt.leaf_entry(pa, perm);
        if old == new {
            return Ok(false);
        }
        self.set(mem, table, idx, new);
        Ok(true)
    }

    /// Unmap the page at `iova`. Returns whether it was mapped. Emptied
    /// tables stay allocated until [`IoPageTable::destroy`].
    pub fn unmap_page(&mut self, mem: &dyn TableMem, iova: u64) -> Result<bool, PtError> {
        match self.leaf_slot(mem, iova)? {
            Some((table, idx)) => {
                let was = self.fmt.is_present(rd64(mem, table, idx));
                self.set(mem, table, idx, 0);
                Ok(was)
            }
            None => Ok(false),
        }
    }

    /// The physical address and permission `iova` translates to, if mapped.
    pub fn lookup(&self, mem: &dyn TableMem, iova: u64) -> Option<(u64, Perm)> {
        let (table, idx) = self.leaf_slot(mem, iova).ok()??;
        let e = rd64(mem, table, idx);
        if self.fmt.is_present(e) {
            Some((self.fmt.entry_pa(e), self.fmt.leaf_perm(e)))
        } else {
            None
        }
    }

    /// The (table, index) of the leaf entry for `iova`, or `None` when an
    /// upper table on the way is absent.
    fn leaf_slot(&self, mem: &dyn TableMem, iova: u64) -> Result<Option<(u64, usize)>, PtError> {
        if !self.fmt.contains(iova) {
            return Err(PtError::OutOfRange);
        }
        let mut table = self.root;
        for level in (1..self.fmt.levels).rev() {
            let e = rd64(mem, table, index(level, iova));
            if !self.fmt.is_present(e) {
                return Ok(None);
            }
            if self.fmt.is_upper_leaf(e) {
                return Err(PtError::Corrupt);
            }
            table = self.fmt.entry_pa(e);
        }
        Ok(Some((table, index(0, iova))))
    }
}
