// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// RISC-V Sv39 MMU definitions.
///
/// Sv39 uses 3-level page tables with 39-bit virtual addresses:
///   [38:30] VPN[2]  (9 bits)
///   [29:21] VPN[1]  (9 bits)
///   [20:12] VPN[0]  (9 bits)
///   [11:0]  Offset  (12 bits)

use bitflags::bitflags;

/// Number of entries per page table (512).
pub const PT_ENTRIES: usize = 512;

/// Page size in bytes (4 KiB).
pub const PAGE_SIZE: usize = 4096;

/// log2(PAGE_SIZE).
pub const PAGE_SHIFT: usize = 12;

bitflags! {
    /// Sv39 Page Table Entry flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PteFlags: u64 {
        const VALID    = 1 << 0;
        const READ     = 1 << 1;
        const WRITE    = 1 << 2;
        const EXEC     = 1 << 3;
        const USER     = 1 << 4;
        const GLOBAL   = 1 << 5;
        const ACCESSED = 1 << 6;
        const DIRTY    = 1 << 7;
        /// OS-defined: Copy-on-Write flag (bit 8, in RSW field).
        const COW      = 1 << 8;
        /// OS-defined: Demand-mapped page (bit 9, in RSW field).
        /// PTE is invalid but marks a reserved virtual range (allocate on fault).
        const DEMAND   = 1 << 9;

        // Common combinations — kernel mappings pre-set A+D to avoid page faults
        // on RISC-V implementations with software-managed A/D bits (ADUE=0).
        const KERNEL_RO  = Self::VALID.bits() | Self::READ.bits() | Self::ACCESSED.bits();
        const KERNEL_RW  = Self::VALID.bits() | Self::READ.bits() | Self::WRITE.bits() | Self::ACCESSED.bits() | Self::DIRTY.bits();
        const KERNEL_RX  = Self::VALID.bits() | Self::READ.bits() | Self::EXEC.bits() | Self::ACCESSED.bits();
        const KERNEL_RWX = Self::VALID.bits() | Self::READ.bits() | Self::WRITE.bits() | Self::EXEC.bits() | Self::ACCESSED.bits() | Self::DIRTY.bits();
        const USER_RO    = Self::VALID.bits() | Self::READ.bits() | Self::USER.bits();
        const USER_RW    = Self::VALID.bits() | Self::READ.bits() | Self::WRITE.bits() | Self::USER.bits();
        const USER_RX    = Self::VALID.bits() | Self::READ.bits() | Self::EXEC.bits() | Self::USER.bits();
    }
}

/// A single Sv39 page table entry (64 bits).
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Pte(pub u64);

impl Pte {
    /// PPN is stored in bits [53:10].
    const PPN_SHIFT: u32 = 10;

    /// Create a new PTE from a physical page number (already shifted >> 12)
    /// and flags.
    #[inline]
    pub fn new(phys_addr: usize, flags: PteFlags) -> Self {
        Self((((phys_addr as u64) >> 12) << Self::PPN_SHIFT) | flags.bits())
    }

    /// Create an empty (invalid) PTE.
    #[inline]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Is this PTE valid?
    #[inline]
    pub fn is_valid(self) -> bool {
        self.0 & PteFlags::VALID.bits() != 0
    }

    /// Is this a leaf PTE (has R, W, or X)?
    #[inline]
    pub fn is_leaf(self) -> bool {
        self.0 & (PteFlags::READ.bits() | PteFlags::WRITE.bits() | PteFlags::EXEC.bits()) != 0
    }

    /// Extract the physical address this PTE points to.
    #[inline]
    pub fn phys_addr(self) -> usize {
        ((self.0 >> Self::PPN_SHIFT) << 12) as usize
    }

    /// Get the flags portion of this PTE.
    #[inline]
    pub fn flags(self) -> PteFlags {
        PteFlags::from_bits_truncate(self.0)
    }

    /// Raw u64 value.
    #[inline]
    pub fn bits(self) -> u64 {
        self.0
    }
}

/// Extract VPN[2] from a virtual address (bits [38:30]).
#[inline]
pub fn vpn2(va: usize) -> usize {
    (va >> 30) & 0x1FF
}

/// Extract VPN[1] from a virtual address (bits [29:21]).
#[inline]
pub fn vpn1(va: usize) -> usize {
    (va >> 21) & 0x1FF
}

/// Extract VPN[0] from a virtual address (bits [20:12]).
#[inline]
pub fn vpn0(va: usize) -> usize {
    (va >> 12) & 0x1FF
}

/// Build a SATP register value for Sv39 mode.
/// `root_ppn` is the physical page number of the root page table.
/// `asid` is the address space identifier (0 for now).
#[inline]
pub fn make_satp(root_pt_phys: usize, asid: u16) -> usize {
    let mode: usize = 8; // Sv39
    let ppn = root_pt_phys >> 12;
    (mode << 60) | ((asid as usize) << 44) | ppn
}

/// Round address up to next page boundary.
#[inline]
pub const fn page_align_up(addr: usize) -> usize {
    (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// Round address down to page boundary.
#[inline]
pub const fn page_align_down(addr: usize) -> usize {
    addr & !(PAGE_SIZE - 1)
}

/// Check if an address is page-aligned.
#[inline]
pub const fn is_page_aligned(addr: usize) -> bool {
    addr & (PAGE_SIZE - 1) == 0
}
