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

// Virtual KASLR (Kconfig `KASLR`): the image window and the image bias are
// pure and host-tested; the boot half (the Zkr draw, the relocation walk, the
// boot root) is bare-metal only.
//
// The `#[path]`s are the same file in the crate and in the host suites that
// pull this file in by path (`tests/host/arch-tests`), where a nested `mod`
// would otherwise be looked up beside the including file.
#[path = "mmu/kaslr.rs"]
pub mod kaslr;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
#[path = "mmu/kaslr_boot.rs"]
pub mod kaslr_boot;

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
        /// Svpbmt PBMT field, bits 62:61: `01` = NC (normal, non-cacheable,
        /// weakly ordered), `10` = IO (device, strongly ordered), `00` = the
        /// PMA's own type. Only written once [`svpbmt_select`] found the
        /// extension; on a hart without it a non-zero field is a page fault.
        const PBMT_NC  = 1 << 61;
        const PBMT_IO  = 1 << 62;

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

/// The 44 bits of PPN in a PTE, below the Svpbmt and Svnapot bits.
const PPN_MASK: u64 = (1 << 44) - 1;

/// Svnapot's N bit (PTE bit 63): the leaf is one naturally aligned 64 KiB
/// translation, PPN[3:0] = `0b1000`. See `ext::napot`.
pub const PTE_N: u64 = 1 << 63;

/// Svpbmt (page-based memory types): the memory type of a leaf is encoded
/// in PTE bits 62:61 when the extension is on, and the PMA decides when it
/// is not. Decided once at boot from the device tree and the Kconfig policy
/// (`RV_SVPBMT`); the encoder emits the field only when it is on.
static SVPBMT_ON: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Settle Svpbmt: on only when the policy allows it and cpu@0's `riscv,isa`
/// lists it. The firmware (OpenSBI) sets `menvcfg.PBMTE` for a hart that
/// implements the extension; there is no S-mode way to enable it. Returns
/// the decision.
pub fn svpbmt_select(policy_allows: bool, dt_present: bool) -> bool {
    let on = policy_allows && dt_present;
    SVPBMT_ON.store(on, core::sync::atomic::Ordering::Release);
    on
}

/// Is the PBMT field in use?
#[inline]
pub fn svpbmt_on() -> bool {
    SVPBMT_ON.load(core::sync::atomic::Ordering::Acquire)
}

/// Svadu (hardware update of the A and D bits): when it is on, a leaf with A
/// clear is not a fault, the hart sets A itself, and page aging
/// (`Mmu::harvest_accessed`) costs no fault. Without it the Svade rule holds
/// (a leaf with A clear faults) and the fault path resolves the A fault in
/// software (`Mmu::resolve_accessed_fault`). Svadu is enabled by the
/// firmware (`menvcfg.ADUE`, M-mode only; OpenSBI sets it for a hart whose
/// device tree declares `svadu`), and S-mode has no register to read it
/// back, so the device tree's token is the whole probe, as for Svpbmt: a
/// firmware that declares the extension and leaves it off costs a fault per
/// aged page, never a wrong answer, because the software path runs for
/// every A fault whatever this says.
static SVADU_ON: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Settle Svadu (Kconfig `RV_SVADU`): on only when the policy allows it and
/// cpu@0's `riscv,isa` lists it. Returns the decision.
pub fn svadu_select(policy_allows: bool, dt_present: bool) -> bool {
    let on = policy_allows && dt_present;
    SVADU_ON.store(on, core::sync::atomic::Ordering::Release);
    on
}

/// Does the hart set the Accessed bit itself?
#[inline]
pub fn svadu_on() -> bool {
    SVADU_ON.load(core::sync::atomic::Ordering::Acquire)
}

/// The PBMT bits for a memory type: `WB` is the PMA's type (0), `WC` and
/// `NC` the one non-cacheable normal type, `Device` IO. Zero while
/// Svpbmt is off, so every memory type is the plain PTE.
#[inline]
pub fn pbmt_bits(mem_nc: bool, mem_io: bool) -> u64 {
    if !svpbmt_on() { 0 }
    else if mem_io { PteFlags::PBMT_IO.bits() }
    else if mem_nc { PteFlags::PBMT_NC.bits() }
    else { 0 }
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
        // PPN is bits [53:10]; 62:61 (Svpbmt) and 63 (Svnapot) are not part of it.
        // With N set, PPN[3:0] is the size marker `0b1000`, not address: the
        // word names the 64 KiB run's base, and the caller adds the offset
        // inside the run (`Mmu::pte_leaf0_span`). Branch-free: this is read on
        // every software walk.
        let napot = (((self.0 as i64) >> 63) as u64) & 0xF;
        ((((self.0 >> Self::PPN_SHIFT) & PPN_MASK) & !napot) << 12) as usize
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

/// Is `word` a valid leaf with the software COW bit set? A page marker's flag
/// is that same bit (RSW 8), so a word that is not valid is never COW.
#[inline]
pub const fn is_cow(word: u64) -> bool {
    const BOTH: u64 = PteFlags::VALID.bits() | PteFlags::COW.bits();
    word & BOTH == BOTH
}

// ── Page markers (arch-api `PageMarker`) ─────────────────────────────────

/// The marker flag of a not-present page marker: RSW bit 8 (the COW position,
/// which a leaf alone uses) with VALID clear and the DEMAND bit (bit 9) clear.
/// A walker ignores every bit of a word with V = 0, so the rest is free.
pub const MARKER_FLAG: u64 = PteFlags::COW.bits();
/// The two-bit kind code sits at bits 11:10, clear of R/W/X (bits 3:1) so
/// that [`Pte::is_leaf`], which does not look at V, still says "not a leaf".
const MARKER_KIND_SHIFT: u32 = 10;
/// The 32-bit payload fills bits 63:32.
const MARKER_PAYLOAD_SHIFT: u32 = 32;

/// A page marker of kind `code` (1..=3, `PageMarker::code`) carrying `payload`.
#[inline]
pub const fn make_marker(code: u8, payload: u32) -> u64 {
    MARKER_FLAG | (((code & 3) as u64) << MARKER_KIND_SHIFT) | ((payload as u64) << MARKER_PAYLOAD_SHIFT)
}

/// `(code, payload)` of a page marker; `None` for any other word.
#[inline]
pub const fn marker_of(word: u64) -> Option<(u8, u32)> {
    if word & (PteFlags::VALID.bits() | PteFlags::DEMAND.bits() | MARKER_FLAG) != MARKER_FLAG {
        return None;
    }
    let code = ((word >> MARKER_KIND_SHIFT) & 3) as u8;
    if code == 0 {
        return None;
    }
    Some((code, (word >> MARKER_PAYLOAD_SHIFT) as u32))
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
