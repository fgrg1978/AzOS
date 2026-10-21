// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The G-stage page table: guest-physical to host-physical translation for a
//! VS/VU-mode guest (`hgatp`, RISC-V privileged spec 1.12, "Guest-Physical
//! Address Translation").
//!
//! G-stage is the Sv39/Sv48 PTE format with three differences this file
//! keeps straight, because each one fails silently as a guest page fault:
//!
//! * **Root is 16 KiB.** The guest-physical address is two bits wider than
//!   the virtual one (Sv39x4: 41 bits, Sv48x4: 50), so the root table has
//!   2048 entries, four contiguous pages, 16 KiB aligned. `hgatp.PPN` of the
//!   root has its low two bits zero. Interior tables are ordinary 4 KiB.
//! * **Every access is a user access.** A leaf needs `U=1` or the walk faults,
//!   whatever the guest's privilege. Non-leaf PTEs keep `U`, `A`, `D` clear
//!   (reserved), and `G` is reserved everywhere.
//! * **No software A/D.** Without Svadu a clear `A` (or a clear `D` on a
//!   write) faults instead of being updated; the encoder presets `A` always
//!   and `D` on writable leaves, so a first touch never exits.
//!
//! The builder works through [`TableMem`], not raw pointers: the host tests
//! drive it over a simulated physical memory, and the kernel implements it
//! over the frame allocator (S6).

// ── PTE encoding ────────────────────────────────────────────────────────
pub const PTE_V: u64 = 1 << 0;
pub const PTE_R: u64 = 1 << 1;
pub const PTE_W: u64 = 1 << 2;
pub const PTE_X: u64 = 1 << 3;
pub const PTE_U: u64 = 1 << 4;
pub const PTE_G: u64 = 1 << 5;
pub const PTE_A: u64 = 1 << 6;
pub const PTE_D: u64 = 1 << 7;
const PTE_PPN_SHIFT: u32 = 10;
/// A PTE's PPN is bits 53:10 (44 bits): physical addresses up to 56 bits.
const PTE_PPN_MASK: u64 = ((1 << 44) - 1) << PTE_PPN_SHIFT;
/// Host-physical addresses are below 2^56.
pub const PA_LIMIT: u64 = 1 << 56;

const PAGE_SHIFT: u32 = 12;
const PAGE_BYTES: u64 = 1 << PAGE_SHIFT;
/// Pages in a root table (2048 entries x 8 bytes).
pub const ROOT_PAGES: usize = 4;
const ROOT_ENTRIES: usize = 2048;
const TABLE_ENTRIES: usize = 512;

/// Access rights of a leaf. Read-write-execute combinations the spec
/// reserves (`W` without `R`) and the empty set (it would read as a table
/// pointer) cannot be built: see [`GPerms::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GPerms {
    r: bool,
    w: bool,
    x: bool,
}

/// What a guest access needs from a leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Fetch,
    Load,
    Store,
}

impl GPerms {
    pub const RO: GPerms = GPerms { r: true, w: false, x: false };
    pub const RW: GPerms = GPerms { r: true, w: true, x: false };
    pub const RX: GPerms = GPerms { r: true, w: false, x: true };
    pub const RWX: GPerms = GPerms { r: true, w: true, x: true };
    /// Execute-only is legal in G-stage (R=0, X=1).
    pub const X: GPerms = GPerms { r: false, w: false, x: true };

    /// `None` for the empty set and for write without read.
    pub const fn new(r: bool, w: bool, x: bool) -> Option<GPerms> {
        if (!r && !w && !x) || (w && !r) {
            None
        } else {
            Some(GPerms { r, w, x })
        }
    }

    pub const fn readable(self) -> bool { self.r }
    pub const fn writable(self) -> bool { self.w }
    pub const fn executable(self) -> bool { self.x }

    pub const fn allows(self, a: Access) -> bool {
        match a {
            Access::Fetch => self.x,
            Access::Load => self.r,
            Access::Store => self.w,
        }
    }

    const fn bits(self) -> u64 {
        (if self.r { PTE_R } else { 0 })
            | (if self.w { PTE_W | PTE_D } else { 0 })
            | (if self.x { PTE_X } else { 0 })
    }
}

/// A leaf PTE: `V`, the rights, `U` (G-stage accesses are user accesses),
/// `A` preset, `D` preset when writable.
pub const fn leaf_pte(hpa: u64, perms: GPerms) -> u64 {
    ((hpa >> PAGE_SHIFT) << PTE_PPN_SHIFT) | PTE_V | PTE_U | PTE_A | perms.bits()
}

/// A pointer to the next-level table: `V` and the PPN, every other bit zero.
pub const fn table_pte(table_pa: u64) -> u64 {
    ((table_pa >> PAGE_SHIFT) << PTE_PPN_SHIFT) | PTE_V
}

pub const fn pte_valid(pte: u64) -> bool {
    pte & PTE_V != 0
}

/// A valid PTE with any of R/W/X is a leaf; with none, a table pointer.
pub const fn pte_is_leaf(pte: u64) -> bool {
    pte & (PTE_R | PTE_W | PTE_X) != 0
}

/// The physical address a PTE names (the next table, or the leaf's base).
pub const fn pte_pa(pte: u64) -> u64 {
    ((pte & PTE_PPN_MASK) >> PTE_PPN_SHIFT) << PAGE_SHIFT
}

/// The rights of a leaf PTE, `None` for a reserved combination.
pub const fn pte_perms(pte: u64) -> Option<GPerms> {
    GPerms::new(pte & PTE_R != 0, pte & PTE_W != 0, pte & PTE_X != 0)
}

// ── modes and page sizes ────────────────────────────────────────────────
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// 3 levels, 41-bit guest-physical space.
    Sv39x4,
    /// 4 levels, 50-bit guest-physical space.
    Sv48x4,
}

impl Mode {
    /// The `hgatp.MODE` value.
    pub const fn hgatp_mode(self) -> u64 {
        match self {
            Mode::Sv39x4 => super::csr::HGATP_MODE_SV39X4,
            Mode::Sv48x4 => super::csr::HGATP_MODE_SV48X4,
        }
    }

    pub const fn from_hgatp_mode(m: u64) -> Option<Mode> {
        match m {
            super::csr::HGATP_MODE_SV39X4 => Some(Mode::Sv39x4),
            super::csr::HGATP_MODE_SV48X4 => Some(Mode::Sv48x4),
            _ => None,
        }
    }

    /// Level of the root table (the highest leaf level a mapping may use).
    pub const fn root_level(self) -> u8 {
        match self {
            Mode::Sv39x4 => 2,
            Mode::Sv48x4 => 3,
        }
    }

    /// Guest-physical address width in bits.
    pub const fn gpa_bits(self) -> u32 {
        PAGE_SHIFT + 9 * (self.root_level() as u32) + 11
    }
}

/// A leaf's size: the level it sits at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PageSize {
    K4 = 0,
    M2 = 1,
    G1 = 2,
    G512 = 3,
}

impl PageSize {
    pub const fn level(self) -> u8 { self as u8 }
    pub const fn bytes(self) -> u64 { 1 << (PAGE_SHIFT + 9 * self as u32) }
    const ALL: [PageSize; 4] = [PageSize::G512, PageSize::G1, PageSize::M2, PageSize::K4];
}

/// Why a map or unmap was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    /// The page size needs a level this mode does not have.
    BadSize,
    /// An address is not aligned to the page size (or a range to a page).
    Misaligned,
    /// The guest-physical address is beyond the mode's space, or the host
    /// address beyond 56 bits.
    OutOfRange,
    /// A leaf already sits there.
    AlreadyMapped,
    /// A larger leaf covers it, or smaller pages are mapped under it.
    Overlap,
    /// Nothing is mapped there.
    NotMapped,
    /// The table allocator is out of pages.
    NoMemory,
}

/// Where the page tables live. `alloc` returns zeroed, contiguous,
/// `pages * 4096`-aligned memory (1 for an interior table, [`ROOT_PAGES`] for
/// a root); `read`/`write` access one 8-byte entry of a table by its base.
pub trait TableMem {
    fn alloc(&mut self, pages: usize) -> Option<u64>;
    fn free(&mut self, pa: u64, pages: usize);
    fn read(&self, table: u64, index: usize) -> u64;
    fn write(&mut self, table: u64, index: usize, pte: u64);
}

/// A resolved guest-physical address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Translation {
    pub hpa: u64,
    pub perms: GPerms,
    pub size: PageSize,
}

/// One VM's G-stage table. Holds no memory itself: the tables are in the
/// [`TableMem`] it is used with, freed by [`GStage::destroy`].
#[derive(Clone, Copy, Debug)]
pub struct GStage {
    root: u64,
    mode: Mode,
}

const fn index_of(gpa: u64, level: u8, mode: Mode) -> usize {
    let mask = if level == mode.root_level() { 0x7FF } else { 0x1FF };
    ((gpa >> (PAGE_SHIFT + 9 * level as u32)) & mask) as usize
}

const fn entries_at(level: u8, mode: Mode) -> usize {
    if level == mode.root_level() { ROOT_ENTRIES } else { TABLE_ENTRIES }
}

impl GStage {
    /// A table with an empty 16 KiB root.
    pub fn new<M: TableMem>(mem: &mut M, mode: Mode) -> Option<GStage> {
        let root = mem.alloc(ROOT_PAGES)?;
        if root % (ROOT_PAGES as u64 * PAGE_BYTES) != 0 || root >= PA_LIMIT {
            mem.free(root, ROOT_PAGES);
            return None;
        }
        Some(GStage { root, mode })
    }

    pub const fn root(&self) -> u64 { self.root }
    pub const fn mode(&self) -> Mode { self.mode }

    /// The `hgatp` value: mode, VMID (14 bits on RV64), root PPN.
    pub const fn hgatp(&self, vmid: u16) -> u64 {
        (self.mode.hgatp_mode() << super::csr::HGATP_MODE_SHIFT)
            | (((vmid as u64) << super::csr::HGATP_VMID_SHIFT) & super::csr::HGATP_VMID_MASK)
            | (self.root >> PAGE_SHIFT)
    }

    /// Map one leaf of `size`. Interior tables are allocated on the way
    /// down. The caller issues the `hfence.gvma` ([`hfence_gvma_page`]).
    pub fn map<M: TableMem>(
        &self,
        mem: &mut M,
        gpa: u64,
        hpa: u64,
        size: PageSize,
        perms: GPerms,
    ) -> Result<(), MapError> {
        let leaf_level = size.level();
        if leaf_level > self.mode.root_level() {
            return Err(MapError::BadSize);
        }
        if gpa & (size.bytes() - 1) != 0 || hpa & (size.bytes() - 1) != 0 {
            return Err(MapError::Misaligned);
        }
        if gpa >> self.mode.gpa_bits() != 0 || hpa >= PA_LIMIT {
            return Err(MapError::OutOfRange);
        }
        let mut table = self.root;
        let mut level = self.mode.root_level();
        while level > leaf_level {
            let idx = index_of(gpa, level, self.mode);
            let pte = mem.read(table, idx);
            table = if !pte_valid(pte) {
                let next = mem.alloc(1).ok_or(MapError::NoMemory)?;
                mem.write(table, idx, table_pte(next));
                next
            } else if pte_is_leaf(pte) {
                return Err(MapError::Overlap);
            } else {
                pte_pa(pte)
            };
            level -= 1;
        }
        let idx = index_of(gpa, leaf_level, self.mode);
        let old = mem.read(table, idx);
        if pte_valid(old) {
            return Err(if pte_is_leaf(old) { MapError::AlreadyMapped } else { MapError::Overlap });
        }
        mem.write(table, idx, leaf_pte(hpa, perms));
        Ok(())
    }

    /// Map `len` bytes (a multiple of 4 KiB) with the largest leaves the
    /// alignment of both addresses and the remaining length allow, none
    /// larger than `max`. Stops at the first error; what was mapped stays.
    pub fn map_range<M: TableMem>(
        &self,
        mem: &mut M,
        mut gpa: u64,
        mut hpa: u64,
        mut len: u64,
        perms: GPerms,
        max: PageSize,
    ) -> Result<(), MapError> {
        if (gpa | hpa | len) & (PAGE_BYTES - 1) != 0 {
            return Err(MapError::Misaligned);
        }
        while len > 0 {
            let size = PageSize::ALL
                .into_iter()
                .find(|s| {
                    *s <= max
                        && s.level() <= self.mode.root_level()
                        && (gpa | hpa) & (s.bytes() - 1) == 0
                        && len >= s.bytes()
                })
                .unwrap_or(PageSize::K4);
            self.map(mem, gpa, hpa, size, perms)?;
            gpa += size.bytes();
            hpa += size.bytes();
            len -= size.bytes();
        }
        Ok(())
    }

    /// Remove the leaf of exactly `size` at `gpa`, returning the host
    /// address it mapped. Interior tables stay until [`GStage::destroy`].
    /// The caller issues the `hfence.gvma`.
    pub fn unmap<M: TableMem>(&self, mem: &mut M, gpa: u64, size: PageSize) -> Result<u64, MapError> {
        if size.level() > self.mode.root_level() {
            return Err(MapError::BadSize);
        }
        if gpa & (size.bytes() - 1) != 0 {
            return Err(MapError::Misaligned);
        }
        if gpa >> self.mode.gpa_bits() != 0 {
            return Err(MapError::OutOfRange);
        }
        let mut table = self.root;
        let mut level = self.mode.root_level();
        loop {
            let idx = index_of(gpa, level, self.mode);
            let pte = mem.read(table, idx);
            if !pte_valid(pte) {
                return Err(MapError::NotMapped);
            }
            if level == size.level() {
                if !pte_is_leaf(pte) {
                    return Err(MapError::Overlap);
                }
                mem.write(table, idx, 0);
                return Ok(pte_pa(pte));
            }
            if pte_is_leaf(pte) {
                return Err(MapError::Overlap);
            }
            table = pte_pa(pte);
            level -= 1;
        }
    }

    /// The software walk the hardware does: `None` where it would fault
    /// (invalid, a reserved rights combination, or a misaligned superpage).
    pub fn walk<M: TableMem>(&self, mem: &M, gpa: u64) -> Option<Translation> {
        if gpa >> self.mode.gpa_bits() != 0 {
            return None;
        }
        let mut table = self.root;
        let mut level = self.mode.root_level();
        loop {
            let pte = mem.read(table, index_of(gpa, level, self.mode));
            if !pte_valid(pte) {
                return None;
            }
            if pte_is_leaf(pte) {
                let size = PageSize::ALL.into_iter().find(|s| s.level() == level)?;
                let base = pte_pa(pte);
                if base & (size.bytes() - 1) != 0 {
                    return None;
                }
                return Some(Translation {
                    hpa: base | (gpa & (size.bytes() - 1)),
                    perms: pte_perms(pte)?,
                    size,
                });
            }
            if level == 0 {
                return None;
            }
            table = pte_pa(pte);
            level -= 1;
        }
    }

    /// Free every table page, the root included. Leaf targets are the
    /// caller's. The caller has stopped every hart using the VMID.
    pub fn destroy<M: TableMem>(self, mem: &mut M) {
        fn free_tree<M: TableMem>(mem: &mut M, table: u64, level: u8, mode: Mode) {
            if level > 0 {
                for i in 0..entries_at(level, mode) {
                    let pte = mem.read(table, i);
                    if pte_valid(pte) && !pte_is_leaf(pte) {
                        free_tree(mem, pte_pa(pte), level - 1, mode);
                    }
                }
            }
            mem.free(table, if level == mode.root_level() { ROOT_PAGES } else { 1 });
        }
        free_tree(mem, self.root, self.mode.root_level(), self.mode);
    }
}

// ── hfence.gvma / hfence.vvma ───────────────────────────────────────────
// `hfence.gvma rs1, rs2` (funct7 0110001): rs1 = guest-physical address >> 2,
// rs2 = VMID; x0 in either position means "all". Encoded by hand for the
// reason the CSR numbers are (no `h` target feature in the assembler).

/// Base encoding of `hfence.gvma x0, x0` (all guests, all addresses).
pub const HFENCE_GVMA: u32 = 0x6200_0073;
/// Base encoding of `hfence.vvma x0, x0`.
pub const HFENCE_VVMA: u32 = 0x2200_0073;

/// `hfence.gvma` with explicit source registers (register numbers 0..=31).
pub const fn hfence_gvma_word(rs1: u32, rs2: u32) -> u32 {
    HFENCE_GVMA | (rs2 << 20) | (rs1 << 15)
}

const A0: u32 = 10;
const A1: u32 = 11;

/// All G-stage translations of all VMIDs on this hart.
#[cfg(target_arch = "riscv64")]
pub fn hfence_gvma_all() {
    // SAFETY: a fence; no memory or register operand.
    unsafe { core::arch::asm!(".word {w}", w = const HFENCE_GVMA, options(nostack)) };
}

/// All G-stage translations of one VMID on this hart.
#[cfg(target_arch = "riscv64")]
pub fn hfence_gvma_vmid(vmid: u16) {
    // SAFETY: a fence on a1 = VMID.
    unsafe {
        core::arch::asm!(".word {w}", w = const hfence_gvma_word(0, A1), in("a1") vmid as u64,
            options(nostack));
    }
}

/// The translation of one guest-physical page of one VMID on this hart.
#[cfg(target_arch = "riscv64")]
pub fn hfence_gvma_page(gpa: u64, vmid: u16) {
    // SAFETY: a fence on a0 = gpa >> 2, a1 = VMID.
    unsafe {
        core::arch::asm!(".word {w}", w = const hfence_gvma_word(A0, A1),
            in("a0") gpa >> 2, in("a1") vmid as u64, options(nostack));
    }
}

/// Does this hart implement `mode`? `hgatp.MODE` is WARL: a write of an
/// unsupported mode is ignored, so write it and read it back (`hgatp` is
/// restored). Call only when H is [`super::probe::available`].
#[cfg(target_arch = "riscv64")]
pub fn mode_supported(mode: Mode) -> bool {
    let old: u64;
    let back: u64;
    // SAFETY: only `hgatp` is touched, and the host runs with V=0, so
    // nothing translates through it; the old value is restored.
    unsafe {
        core::arch::asm!("csrr {o}, {hgatp}", o = out(reg) old, hgatp = const super::csr::HGATP,
            options(nomem, nostack));
        core::arch::asm!(
            "csrw {hgatp}, {w}",
            "csrr {b}, {hgatp}",
            "csrw {hgatp}, {o}",
            w = in(reg) mode.hgatp_mode() << super::csr::HGATP_MODE_SHIFT,
            b = out(reg) back, o = in(reg) old,
            hgatp = const super::csr::HGATP, options(nomem, nostack));
    }
    back >> super::csr::HGATP_MODE_SHIFT == mode.hgatp_mode()
}
