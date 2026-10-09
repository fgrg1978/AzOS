// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! x86_64 paging: 4-level (PML4) translation, 5-level (LA57) when boot.S
//! turned it on (Kconfig `X86_LA57`), the PTE encoding behind the `Mmu`
//! contract, the CR3 word (PCID), the kernel/user split, and a table walker
//! (map / unmap / protect / translate) over any table memory.
//!
//! **Pure first.** Everything above the `cpu` section is plain arithmetic
//! with no instruction and no crate dependency beyond `azos_arch_api` and
//! `azos_limits`, so `tests/host/arch-tests` pulls this file in with
//! `#[path]` and checks it on the host. The instructions (CR0/CR3/CR4, PAT,
//! `invlpg`, `invpcid`, `stac`/`clac`) are in the `x86_64`-only part at the
//! end.
//!
//! **Levels.** Trait level 0 is the page table (4 KiB leaves), 1 the page
//! directory (PS = 2 MiB leaf), 2 the PDPT (PS = 1 GiB leaf, CPUID
//! PDPE1GB), 3 the PML4, 4 the PML5 under LA57. PS is reserved in PML4/PML5
//! entries, so no leaf exists there.
//!
//! **Bit 7 is PS above level 0 and PAT at level 0.** This port never sets
//! either PAT bit (bit 7 at level 0, bit 12 in a PS leaf): device memory is
//! PCD|PWT, PAT index 3 = UC in [`PAT_VALUE`]. That keeps the attribute
//! decode level-independent, as the `Mmu` contract requires, and keeps bit
//! 12 of every PS leaf zero so [`phys_addr`] needs no level.
//!
//! **TLB tags and the switch.** With CR4.PCIDE the CR3 word carries the task
//! ASID's low 12 bits as the PCID, and bit 63 (no-flush) is NEVER set: a CR3
//! write then invalidates every non-global entry of the incoming PCID, so a
//! CPU never uses a translation cached before its latest switch into that
//! address space. That is today's "full flush on switch" on the other ISAs
//! (VM-DESIGN §0), restated per PCID, and it is what keeps the shootdown
//! rule in `tlb.rs` ("signal the CPUs whose CR3 names the root") sound:
//! entries left under another PCID are unreachable until a switch-in that
//! drops them. Keeping them (P2 of VM-DESIGN §2.4) is [`CR3_NOFLUSH`] plus an
//! ASID allocator with generations; nothing here has to change shape for it.
//!
//! **Global kernel leaves.** Kernel leaves carry G (Kconfig
//! `X86_KERNEL_GLOBAL_PAGES`) so a CR3 write keeps them. Sound only while
//! the kernel half is the same in every root (every user PML4 shares the
//! kernel's upper-half entries, [`KERNEL_HALF_FIRST_SLOT`]); a kernel
//! mapping that changes is dropped by `invlpg` (which drops G entries) or by
//! a full flush that includes globals (`invpcid` type 2 / CR4.PGE toggle).

use azos_arch_api::{MmuError, PagePerms};

/// 4 KiB pages: the only base page x86_64 has.
pub const PAGE_SIZE: usize = azos_arch_api::PAGE_SIZE;
/// log2([`PAGE_SIZE`]).
pub const PAGE_SHIFT: usize = azos_arch_api::PAGE_SHIFT;
const _: () = assert!(PAGE_SHIFT == 12, "x86_64 has 4 KiB base pages only");

/// 512 eight-byte entries per table, at every level.
pub const PT_ENTRIES: usize = 512;
/// VA bits each level indexes.
pub const IDX_BITS: usize = 9;
/// Levels of 4-level paging (PML4).
pub const LEVELS_4: usize = 4;
/// Levels of 5-level paging (CR4.LA57, PML5).
pub const LEVELS_5: usize = 5;
/// The deepest level a leaf may sit at (PDPT, 1 GiB).
pub const MAX_LEAF_LEVEL: usize = 2;

// ── PTE bits (Intel SDM Vol. 3A §4.5, tables 4-15..4-20) ──────────────────

/// Present.
pub const P: u64 = 1 << 0;
/// Writable (CR0.WP makes it bind the kernel too).
pub const RW: u64 = 1 << 1;
/// User (CPL 3) may access. Effective only when set at every level.
pub const US: u64 = 1 << 2;
/// Page-level write-through (PAT index bit 0).
pub const PWT: u64 = 1 << 3;
/// Page-level cache disable (PAT index bit 1).
pub const PCD: u64 = 1 << 4;
/// Accessed (set by the walker).
pub const A: u64 = 1 << 5;
/// Dirty (set by the walker on a write; leaves only).
pub const D: u64 = 1 << 6;
/// Page size: a leaf at level 1 (2 MiB) or 2 (1 GiB).
pub const PS: u64 = 1 << 7;
/// PAT index bit 2 of a level-0 leaf (same position as [`PS`]). Never set.
pub const PAT_4K: u64 = 1 << 7;
/// Global: survives a CR3 write (CR4.PGE). Kernel leaves only.
pub const G: u64 = 1 << 8;
/// Software (ignored by the walker): copy-on-write shared leaf.
pub const SW_COW: u64 = 1 << 9;
/// Software: demand-reserved slot. Meaningful only with [`P`] clear.
pub const SW_DEMAND: u64 = 1 << 10;
/// PAT index bit 2 of a PS leaf. Never set.
pub const PAT_HUGE: u64 = 1 << 12;
/// Execute-disable (EFER.NXE; reserved, and a #PF, without it).
pub const NX: u64 = 1 << 63;

/// Physical address bits 12..51 (52 = the architectural MAXPHYADDR limit;
/// CPUID.80000008H:EAX[7:0] may be lower, and a PA above it is a
/// reserved-bit #PF, so callers only pass frames the firmware reported).
pub const PHYS_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// The attribute bits a leaf's permissions occupy (what `protect` rewrites).
const ATTR_MASK: u64 = RW | US | PWT | PCD | A | D | G | NX;

// ── Geometry ──────────────────────────────────────────────────────────────

/// The VA shift of trait `level`: 12, 21, 30, 39, 48.
#[inline]
pub const fn level_shift(level: usize) -> usize {
    PAGE_SHIFT + IDX_BITS * level
}

/// Bytes one entry at `level` spans: 4 KiB, 2 MiB, 1 GiB, 512 GiB, 256 TiB.
#[inline]
pub const fn level_size(level: usize) -> usize {
    1 << level_shift(level)
}

/// The index into the table at trait `level` that `va` selects. The same
/// split for both depths: LA57 only adds level 4 above.
#[inline]
pub const fn vpn(va: usize, level: usize) -> usize {
    (va >> level_shift(level)) & (PT_ENTRIES - 1)
}

/// Bits of a linear address under `levels`-level paging (48 or 57).
#[inline]
pub const fn va_bits(levels: usize) -> usize {
    level_shift(levels)
}

/// Is `va` canonical under `levels`-level paging: bits 63..va_bits-1 all
/// equal? A non-canonical access is a #GP, not a #PF.
#[inline]
pub const fn is_canonical(va: usize, levels: usize) -> bool {
    let top = (va as i64) >> (va_bits(levels) - 1);
    top == 0 || top == -1
}

// ── Kernel / user split ──────────────────────────────────────────────────
//
// The same split as aarch64's TTBR0/TTBR1 and Sv39's two halves: the lower
// canonical half is user space, the upper half the kernel's. In 4-level
// paging that is PML4 slots 0..255 / 256..511; under LA57, PML5 slots
// 0..255 / 256..511. Every user root shares the kernel's upper-half entries
// (the same next-level tables), so the kernel half is one set of tables.

/// First root slot of the kernel half (the root's upper 256 entries).
pub const KERNEL_HALF_FIRST_SLOT: usize = PT_ENTRIES / 2;

/// One past the highest user VA under `levels`-level paging (128 TiB with
/// 4 levels, 64 PiB with LA57). The last page below it stays unmapped (the
/// guard Linux keeps against `sysret` to a non-canonical RIP).
#[inline]
pub const fn user_top(levels: usize) -> usize {
    1 << (va_bits(levels) - 1)
}

/// Base of the kernel's direct map of physical memory: the first address of
/// the 4-level upper half (PML4 slot 256). Canonical under LA57 too (it
/// sits in PML5 slot 511), so one constant serves both depths; the map
/// covers up to 64 TiB of RAM (slots 256..383) before it reaches
/// [`KERNEL_IMAGE_BASE`]'s slot. `phys_to_virt(pa) = pa | KERNEL_VA_OFFSET`
/// (bits 0..46 are clear), the aarch64 idiom.
///
/// Not yet the offset `crates/core/mm/src/addr.rs` applies: the kernel still
/// runs on boot.S's identity map until it is linked high, and mm keeps
/// offset 0 on x86_64 until then.
pub const KERNEL_VA_OFFSET: u64 = 0xFFFF_8000_0000_0000;
/// Link address of the kernel image: the top 2 GiB (`-mcmodel=kernel`,
/// PML4 slot 511), as Linux's `__START_KERNEL_map`.
pub const KERNEL_IMAGE_BASE: u64 = 0xFFFF_FFFF_8000_0000;
const _: () = assert!(KERNEL_VA_OFFSET & ((1 << 47) - 1) == 0);
const _: () = assert!(vpn(KERNEL_VA_OFFSET as usize, 3) == KERNEL_HALF_FIRST_SLOT);
const _: () = assert!(vpn(KERNEL_IMAGE_BASE as usize, 3) == PT_ENTRIES - 1);

/// Is `va` in the user half (under either depth's lower canonical half)?
#[inline]
pub const fn is_user_va(va: usize, levels: usize) -> bool {
    va < user_top(levels)
}

// ── PAT ──────────────────────────────────────────────────────────────────

/// IA32_PAT.
pub const IA32_PAT: u32 = 0x277;
/// PAT memory types.
pub const PAT_UC: u64 = 0x00;
pub const PAT_WC: u64 = 0x01;
pub const PAT_WT: u64 = 0x04;
pub const PAT_WP: u64 = 0x05;
pub const PAT_WB: u64 = 0x06;
pub const PAT_UC_MINUS: u64 = 0x07;
/// The PAT this kernel programs: Linux's layout (index 0 WB, 1 WC, 2 UC-,
/// 3 UC, 4 WB, 5 WP, 6 UC-, 7 WT). The PTE selects index
/// `PAT:PCD:PWT`; this port uses index 0 (no bit: normal memory) and 3
/// (PCD|PWT: device memory, UC). Index 1 (WC, PWT alone) is there for a
/// framebuffer mapping later; nothing builds it today.
pub const PAT_VALUE: u64 = PAT_WB
    | (PAT_WC << 8)
    | (PAT_UC_MINUS << 16)
    | (PAT_UC << 24)
    | (PAT_WB << 32)
    | (PAT_WP << 40)
    | (PAT_UC_MINUS << 48)
    | (PAT_WT << 56);

/// The PAT index a word selects (level-0 leaf or PS leaf: this port never
/// sets the PAT bit, so bits PCD:PWT alone).
#[inline]
pub const fn pat_index(word: u64) -> u64 {
    ((word & PCD) >> 3) | ((word & PWT) >> 3)
}

/// The memory type a word gets under [`PAT_VALUE`].
#[inline]
pub const fn memory_type(word: u64) -> u64 {
    (PAT_VALUE >> (8 * pat_index(word))) & 0xFF
}

// ── Runtime paging state (set once per boot by the `cpu` part) ─────────

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Paging depth: [`LEVELS_4`], or [`LEVELS_5`] when boot.S set CR4.LA57.
static LEVELS: AtomicUsize = AtomicUsize::new(LEVELS_4);
/// CPUID.80000001H:EDX[26] and Kconfig `X86_GBPAGES` allow 1 GiB leaves.
static GBPAGES: AtomicBool = AtomicBool::new(false);
/// CR4.PCIDE is set: CR3 carries a PCID.
static PCID_ON: AtomicBool = AtomicBool::new(false);
/// `invpcid` may be executed (CPUID.(7,0):EBX[10] and Kconfig `X86_PCID`).
static INVPCID_ON: AtomicBool = AtomicBool::new(false);
/// CR4.SMAP is set: user accesses need the `stac` window.
static SMAP_ON: AtomicBool = AtomicBool::new(false);

/// Kconfig `X86_LA57` is `n`: the depth is a compile-time 4.
const LA57_NEVER: bool = !azos_arch_api::isa::x86_64::LA57.allowed();
/// Kconfig `X86_KERNEL_GLOBAL_PAGES`.
const KERNEL_GLOBAL: bool = azos_limits::X86_KERNEL_GLOBAL_PAGES;

/// Kconfig `X86_LA57` for boot.S, which picks the depth before long mode:
/// 0 = n, 1 = probe, 2 = require.
#[no_mangle]
pub static AZOS_X86_LA57_POLICY: u32 = match azos_arch_api::isa::x86_64::LA57 {
    azos_arch_api::isa::ExtPolicy::Never => 0,
    azos_arch_api::isa::ExtPolicy::Probe => 1,
    azos_arch_api::isa::ExtPolicy::Require => 2,
};

/// The paging depth this boot runs (4, or 5 under LA57).
#[inline]
pub fn levels() -> usize {
    if LA57_NEVER { LEVELS_4 } else { LEVELS.load(Ordering::Relaxed) }
}

/// Record the depth boot.S chose (`cpu::enable_paging` reads CR4.LA57).
pub fn set_levels(levels: usize) {
    LEVELS.store(if levels == LEVELS_5 && !LA57_NEVER { LEVELS_5 } else { LEVELS_4 }, Ordering::Relaxed);
}

/// May a level-2 (1 GiB) leaf be built?
#[inline]
pub fn gbpages() -> bool {
    GBPAGES.load(Ordering::Relaxed)
}

/// Record the 1 GiB-leaf capability (the boot hook's policy-gated probe).
pub fn set_gbpages(on: bool) {
    GBPAGES.store(on, Ordering::Relaxed);
}

/// Is CR4.PCIDE set on this boot?
#[inline]
pub fn pcid_on() -> bool {
    PCID_ON.load(Ordering::Relaxed)
}

/// May `invpcid` run on this boot?
#[inline]
pub fn invpcid_on() -> bool {
    INVPCID_ON.load(Ordering::Relaxed)
}

/// Is CR4.SMAP set on this boot?
#[inline]
pub fn smap_on() -> bool {
    SMAP_ON.load(Ordering::Relaxed)
}

// ── Descriptor encode / decode ───────────────────────────────────────────

/// The empty word: not present, no software marker.
#[inline]
pub const fn empty() -> u64 { 0 }

/// Present bit.
#[inline]
pub const fn is_valid(word: u64) -> bool { word & P != 0 }

/// A pointer to the next-level table when read AT `level`: present, above
/// level 0, PS clear (PS is reserved in PML4/PML5 entries, so always clear
/// there).
#[inline]
pub const fn is_table(word: u64, level: usize) -> bool {
    level > 0 && is_valid(word) && word & PS == 0
}

/// A leaf when read AT `level`: present, and level 0 (bit 7 is PAT there,
/// not PS), or PS set at level 1 / 2.
#[inline]
pub const fn is_leaf(word: u64, level: usize) -> bool {
    is_valid(word) && (level == 0 || (level <= MAX_LEAF_LEVEL && word & PS != 0))
}

/// The physical address a table pointer or a leaf names (bits 12..51; bit
/// 12 of a PS leaf is the PAT bit, never set by this port, and zero anyway
/// for a 2 MiB-aligned frame).
#[inline]
pub const fn phys_addr(word: u64) -> usize {
    (word & PHYS_MASK) as usize
}

/// A table pointer: P|RW|US. The walker ANDs RW and US over every level
/// and ORs NX, so the leaf alone decides the permissions.
#[inline]
pub const fn make_table(pa: usize) -> u64 {
    ((pa as u64) & PHYS_MASK) | P | RW | US
}

/// The attribute bits `perms` implies, without P / PS / the address. Shared
/// by [`make_leaf`] and [`make_demand`] (which stores them with P clear).
///
/// `read: false` has no x86 encoding (a present page is readable), as on
/// aarch64: `UnrepresentablePerms`. W+X is representable; W^X is mm's rule
/// (`crates/core/mm/src/wx.rs`), as on the other ISAs.
pub const fn attr_bits(perms: PagePerms) -> Result<u64, MmuError> {
    attr_bits_with(perms, KERNEL_GLOBAL)
}

/// [`attr_bits`] with the G policy given (pure; the host tests' form).
pub const fn attr_bits_with(perms: PagePerms, kernel_global: bool) -> Result<u64, MmuError> {
    if !perms.read {
        return Err(MmuError::UnrepresentablePerms);
    }
    let mut a = 0;
    if perms.write { a |= RW; }
    if perms.user {
        a |= US;
    } else if kernel_global {
        a |= G;
    }
    if !perms.exec { a |= NX; }
    if !perms.cache { a |= PCD | PWT; }
    if perms.accessed { a |= A; }
    if perms.dirty { a |= D; }
    Ok(a)
}

/// Decode the attribute bits back into [`PagePerms`]. Level-independent.
pub const fn perms_from_bits(word: u64) -> PagePerms {
    PagePerms {
        read: true,
        write: word & RW != 0,
        exec: word & NX == 0,
        user: word & US != 0,
        cache: word & PCD == 0,
        accessed: word & A != 0,
        dirty: word & D != 0,
    }
}

/// A leaf for `pa` read AT `level`. `pa` must be aligned to the level's
/// span (4 KiB / 2 MiB / 1 GiB); a level-2 leaf needs [`gbpages`]; no leaf
/// exists at level 3 or 4.
pub fn make_leaf(pa: usize, perms: PagePerms, level: usize) -> Result<u64, MmuError> {
    make_leaf_with(pa, perms, level, gbpages())
}

/// [`make_leaf`] with the 1 GiB capability given (pure; the host tests' form).
pub const fn make_leaf_with(pa: usize, perms: PagePerms, level: usize, gb: bool)
    -> Result<u64, MmuError>
{
    if level > MAX_LEAF_LEVEL || (level == MAX_LEAF_LEVEL && !gb) {
        return Err(MmuError::UnrepresentablePerms);
    }
    if pa & (level_size(level) - 1) != 0 {
        return Err(MmuError::NotAligned);
    }
    if (pa as u64) & !PHYS_MASK != 0 {
        return Err(MmuError::BadPhys);
    }
    let attrs = match attr_bits(perms) {
        Ok(a) => a,
        Err(e) => return Err(e),
    };
    let ps = if level > 0 { PS } else { 0 };
    Ok((pa as u64) | P | ps | attrs)
}

/// Decode a leaf's permissions.
#[inline]
pub const fn perms_of(word: u64) -> PagePerms { perms_from_bits(word) }

/// The software COW marker.
#[inline]
pub const fn is_cow(word: u64) -> bool { word & SW_COW != 0 }

/// Share a writable leaf copy-on-write: RW off, COW on.
#[inline]
pub const fn share_cow(word: u64) -> u64 { (word & !RW) | SW_COW }

/// Break COW after the private copy: COW off, RW and D on.
#[inline]
pub const fn break_cow(word: u64) -> u64 { (word & !SW_COW) | RW | D }

/// A demand marker: P clear, [`SW_DEMAND`] set, `perms` stored inline (the
/// walker ignores every other bit of a non-present entry). A `!read`
/// request has no encoding and yields the EMPTY word (no reservation), as on
/// aarch64; every `PagePerms` this tree builds has `read`.
#[inline]
pub const fn make_demand(perms: PagePerms) -> u64 {
    match attr_bits(perms) {
        Ok(a) => a | SW_DEMAND,
        Err(_) => 0,
    }
}

/// Not present and demand-marked.
#[inline]
pub const fn is_demand(word: u64) -> bool { !is_valid(word) && word & SW_DEMAND != 0 }

/// The perms a demand marker carries.
#[inline]
pub const fn demand_perms(word: u64) -> PagePerms { perms_from_bits(word) }

// ── CR3 ──────────────────────────────────────────────────────────────────

/// CR3 bits 0..11: the PCID when CR4.PCIDE is set (PWT/PCD otherwise; 0).
pub const CR3_PCID_MASK: u64 = 0xFFF;
/// CR3 bit 63 on a write with PCIDE: keep the incoming PCID's entries.
/// Never set today (see the module doc); the hook P2 retention needs.
pub const CR3_NOFLUSH: u64 = 1 << 63;
/// PCID bits CR3 carries.
pub const PCID_BITS: u32 = 12;

/// The CR3 word for root `root_phys` and scheduler ASID `asid`: the ASID's
/// low 12 bits as the PCID when `pcid` (CR4.PCIDE), else none. The 16-bit
/// ASID truncates harmlessly only because every write flushes the
/// incoming PCID (no [`CR3_NOFLUSH`]).
#[inline]
pub const fn make_cr3(root_phys: usize, asid: u16, pcid: bool) -> u64 {
    let tag = if pcid { (asid as u64) & CR3_PCID_MASK } else { 0 };
    ((root_phys as u64) & PHYS_MASK) | tag
}

/// The root a CR3 word names.
#[inline]
pub const fn cr3_root(cr3: u64) -> usize { (cr3 & PHYS_MASK) as usize }

/// The PCID a CR3 word carries.
#[inline]
pub const fn cr3_pcid(cr3: u64) -> u16 { (cr3 & CR3_PCID_MASK) as u16 }

// ── Table walker ─────────────────────────────────────────────────────────
//
// Generic over the table memory so the same walk runs on the kernel's
// direct map and on a host model in `tests/host/arch-tests`. It edits
// entries only: the caller owns TLB maintenance (`flush_tlb_page` for a
// new or widened mapping, `tlb_shootdown` for a removal, downgrade or
// repoint), as the `Mmu` contract says.

/// The memory page tables live in.
pub trait TableMem {
    /// Entry `idx` of the table at physical `table`.
    fn read(&self, table: usize, idx: usize) -> u64;
    /// Store entry `idx` of the table at physical `table`.
    fn write(&mut self, table: usize, idx: usize, word: u64);
    /// A zeroed, 4 KiB-aligned table frame, or `None` (out of memory).
    fn alloc_table(&mut self) -> Option<usize>;
}

/// Why a walk failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalkError {
    /// The VA is not canonical under this depth.
    NotCanonical,
    /// `va` is not aligned to the requested leaf's span.
    Misaligned,
    /// No frame for an intermediate table.
    NoMemory,
    /// The slot already holds a leaf (or a demand marker).
    AlreadyMapped,
    /// A larger leaf covers the VA: splitting it is the caller's policy.
    HugeLeafInTheWay,
    /// Nothing is mapped at the VA.
    NotMapped,
    /// The leaf could not be encoded.
    Mmu(MmuError),
}

/// A leaf found by [`translate`] or removed by [`unmap`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Leaf {
    /// The leaf word.
    pub word: u64,
    /// The level it sits at (0, 1 or 2).
    pub level: usize,
    /// The physical address `va` translates to (frame + offset in it).
    pub phys: usize,
}

/// The slot holding `va`'s entry at `stop_level`, allocating missing tables
/// on the way down when `alloc`. Returns `(table, index)`.
fn descend<M: TableMem>(mem: &mut M, root: usize, levels: usize, va: usize,
                        stop_level: usize, alloc: bool) -> Result<(usize, usize), WalkError> {
    if !is_canonical(va, levels) {
        return Err(WalkError::NotCanonical);
    }
    let mut table = root;
    let mut level = levels - 1;
    while level > stop_level {
        let idx = vpn(va, level);
        let w = mem.read(table, idx);
        if is_table(w, level) {
            table = phys_addr(w);
        } else if is_leaf(w, level) {
            return Err(WalkError::HugeLeafInTheWay);
        } else if !alloc {
            return Err(WalkError::NotMapped);
        } else if w != 0 {
            // A demand marker above the leaf level: not a table to enter.
            return Err(WalkError::AlreadyMapped);
        } else {
            let t = mem.alloc_table().ok_or(WalkError::NoMemory)?;
            mem.write(table, idx, make_table(t));
            table = t;
        }
        level -= 1;
    }
    Ok((table, vpn(va, stop_level)))
}

/// Map `va` -> `pa` with a leaf at `leaf_level` (0: 4 KiB, 1: 2 MiB,
/// 2: 1 GiB), allocating intermediate tables. `gb` is the 1 GiB capability
/// ([`gbpages`] in the kernel).
#[allow(clippy::too_many_arguments)]
pub fn map<M: TableMem>(mem: &mut M, root: usize, levels: usize, va: usize, pa: usize,
                        leaf_level: usize, perms: PagePerms, gb: bool) -> Result<(), WalkError> {
    if va & (level_size(leaf_level.min(MAX_LEAF_LEVEL)) - 1) != 0 {
        return Err(WalkError::Misaligned);
    }
    let word = make_leaf_with(pa, perms, leaf_level, gb).map_err(WalkError::Mmu)?;
    let (table, idx) = descend(mem, root, levels, va, leaf_level, true)?;
    if mem.read(table, idx) != 0 {
        return Err(WalkError::AlreadyMapped);
    }
    mem.write(table, idx, word);
    Ok(())
}

/// The leaf translating `va`, if any.
pub fn translate<M: TableMem>(mem: &M, root: usize, levels: usize, va: usize) -> Option<Leaf> {
    if !is_canonical(va, levels) {
        return None;
    }
    let mut table = root;
    let mut level = levels - 1;
    loop {
        let w = mem.read(table, vpn(va, level));
        if is_leaf(w, level) {
            let off = va & (level_size(level) - 1);
            return Some(Leaf { word: w, level, phys: phys_addr(w) + off });
        }
        if !is_table(w, level) {
            return None;
        }
        table = phys_addr(w);
        level -= 1;
    }
}

/// Find the slot of the leaf translating `va` (any level).
fn leaf_slot<M: TableMem>(mem: &M, root: usize, levels: usize, va: usize)
    -> Result<(usize, usize, usize), WalkError>
{
    if !is_canonical(va, levels) {
        return Err(WalkError::NotCanonical);
    }
    let mut table = root;
    let mut level = levels - 1;
    loop {
        let idx = vpn(va, level);
        let w = mem.read(table, idx);
        if is_leaf(w, level) {
            return Ok((table, idx, level));
        }
        if !is_table(w, level) {
            return Err(WalkError::NotMapped);
        }
        table = phys_addr(w);
        level -= 1;
    }
}

/// Remove the leaf translating `va` (whatever its size) and return it. The
/// caller shoots the TLB down before freeing the frame. Empty tables are
/// left in place (freeing them is the address space's teardown).
pub fn unmap<M: TableMem>(mem: &mut M, root: usize, levels: usize, va: usize) -> Result<Leaf, WalkError> {
    let (table, idx, level) = leaf_slot(mem, root, levels, va)?;
    let word = mem.read(table, idx);
    mem.write(table, idx, empty());
    Ok(Leaf { word, level, phys: phys_addr(word) + (va & (level_size(level) - 1)) })
}

/// Rewrite the permissions of the leaf translating `va`, keeping its frame,
/// size and software markers. Returns the old word: a downgrade (RW or X
/// removed, US flipped) needs a shootdown, a widening only `flush_tlb_page`.
pub fn protect<M: TableMem>(mem: &mut M, root: usize, levels: usize, va: usize,
                            perms: PagePerms) -> Result<u64, WalkError> {
    let (table, idx, _level) = leaf_slot(mem, root, levels, va)?;
    let old = mem.read(table, idx);
    let attrs = attr_bits(perms).map_err(WalkError::Mmu)?;
    mem.write(table, idx, (old & !ATTR_MASK) | attrs);
    Ok(old)
}

/// Point a user root's kernel half at the kernel's tables: copy root slots
/// [`KERNEL_HALF_FIRST_SLOT`]..512 of `kernel_root` into `user_root`. The
/// kernel half is then ONE set of tables, which is what makes global
/// kernel leaves sound.
pub fn share_kernel_half<M: TableMem>(mem: &mut M, kernel_root: usize, user_root: usize) {
    for i in KERNEL_HALF_FIRST_SLOT..PT_ENTRIES {
        let w = mem.read(kernel_root, i);
        mem.write(user_root, i, w);
    }
}

/// [`TableMem`] over the kernel's own view of physical memory:
/// `table + offset` is a dereferenceable address for every table frame
/// (offset 0 on boot.S's identity map; [`KERNEL_VA_OFFSET`] once the
/// direct map is the kernel's).
pub struct DirectMap<F: FnMut() -> Option<usize>> {
    offset: usize,
    alloc: F,
}

impl<F: FnMut() -> Option<usize>> DirectMap<F> {
    /// # Safety
    /// Every table frame a walk reaches, and every frame `alloc` returns
    /// (zeroed, 4 KiB-aligned), must be mapped writable at `pa + offset`
    /// for the lifetime of the value, and no other CPU may edit the same
    /// tables concurrently (the address-space lock's job).
    pub const unsafe fn new(offset: usize, alloc: F) -> Self {
        Self { offset, alloc }
    }
}

impl<F: FnMut() -> Option<usize>> TableMem for DirectMap<F> {
    #[inline]
    fn read(&self, table: usize, idx: usize) -> u64 {
        // SAFETY: `new`'s contract: the table frame is mapped at +offset.
        unsafe { core::ptr::read_volatile((table + self.offset + idx * 8) as *const u64) }
    }
    #[inline]
    fn write(&mut self, table: usize, idx: usize, word: u64) {
        // SAFETY: as `read`; a single aligned 8-byte store, which the
        // walker of another CPU sees whole.
        unsafe { core::ptr::write_volatile((table + self.offset + idx * 8) as *mut u64, word) }
    }
    #[inline]
    fn alloc_table(&mut self) -> Option<usize> {
        (self.alloc)()
    }
}

// ── The instructions (x86_64 only) ───────────────────────────────────────

/// What the boot found and its Kconfig policies allow, for
/// [`cpu::enable_paging`] and [`cpu::enable_access_protection`].
#[derive(Clone, Copy, Debug, Default)]
pub struct PagingCaps {
    /// CR4.PCIDE (Kconfig `X86_PCID`, CPUID.1:ECX[17]).
    pub pcid: bool,
    /// `invpcid` (Kconfig `X86_PCID`, CPUID.(7,0):EBX[10]).
    pub invpcid: bool,
    /// 1 GiB leaves (Kconfig `X86_GBPAGES`, CPUID.80000001H:EDX[26]).
    pub gbpages: bool,
    /// CR4.SMEP (Kconfig `X86_SMEP`).
    pub smep: bool,
    /// CR4.SMAP (Kconfig `X86_SMAP`).
    pub smap: bool,
}

/// What the control registers read back after an enable step.
#[derive(Clone, Copy, Debug, Default)]
pub struct PagingState {
    pub levels: usize,
    pub nxe: bool,
    pub wp: bool,
    pub pge: bool,
    pub pcide: bool,
    pub smep: bool,
    pub smap: bool,
    pub pat: u64,
}

#[cfg(target_arch = "x86_64")]
pub mod cpu {
    //! CR0/CR3/CR4/EFER/PAT and the TLB instructions. Every caller is CPL 0.

    use super::*;
    use core::arch::asm;

    pub const CR0_WP: u64 = 1 << 16;
    pub const CR4_PGE: u64 = 1 << 7;
    pub const CR4_PCIDE: u64 = 1 << 17;
    pub const CR4_SMEP: u64 = 1 << 20;
    pub const CR4_SMAP: u64 = 1 << 21;
    pub const CR4_LA57: u64 = 1 << 12;
    pub const IA32_EFER: u32 = 0xC000_0080;
    pub const EFER_NXE: u64 = 1 << 11;

    /// `invpcid` types (SDM Vol. 2A, INVPCID).
    pub const INVPCID_ADDR: u64 = 0;
    pub const INVPCID_SINGLE: u64 = 1;
    pub const INVPCID_ALL_GLOBAL: u64 = 2;
    pub const INVPCID_ALL_NONGLOBAL: u64 = 3;

    #[inline(always)]
    pub fn read_cr0() -> u64 {
        let v: u64;
        // SAFETY: reading CR0 has no side effect.
        unsafe { asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags)) };
        v
    }

    #[inline(always)]
    fn write_cr0(v: u64) {
        // SAFETY: callers only set WP on the live value.
        unsafe { asm!("mov cr0, {}", in(reg) v, options(nostack, preserves_flags)) };
    }

    #[inline(always)]
    pub fn read_cr3() -> u64 {
        let v: u64;
        // SAFETY: reading CR3 has no side effect.
        unsafe { asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags)) };
        v
    }

    /// Install a CR3 word. Not `nomem`: every later access walks the new
    /// root, so no memory access may move across it.
    #[inline(always)]
    pub fn write_cr3(v: u64) {
        // SAFETY: the caller passes a root whose kernel half maps the code
        // and stack running here (every root shares it).
        unsafe { asm!("mov cr3, {}", in(reg) v, options(nostack, preserves_flags)) };
    }

    #[inline(always)]
    pub fn read_cr4() -> u64 {
        let v: u64;
        // SAFETY: reading CR4 has no side effect.
        unsafe { asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags)) };
        v
    }

    #[inline(always)]
    fn write_cr4(v: u64) {
        // SAFETY: callers set or clear bits the probe allowed.
        unsafe { asm!("mov cr4, {}", in(reg) v, options(nostack, preserves_flags)) };
    }

    #[inline(always)]
    fn rdmsr(msr: u32) -> u64 {
        let (lo, hi): (u32, u32);
        // SAFETY: an architectural MSR at CPL0.
        unsafe { asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
        ((hi as u64) << 32) | lo as u64
    }

    #[inline(always)]
    fn wrmsr(msr: u32, v: u64) {
        // SAFETY: an architectural MSR at CPL0.
        unsafe { asm!("wrmsr", in("ecx") msr, in("eax") v as u32, in("edx") (v >> 32) as u32, options(nostack, preserves_flags)) };
    }

    /// CPUID.80000001H:EDX[26] (1 GiB pages). `cpuid` clobbers rbx, which
    /// LLVM reserves, hence the save.
    pub fn has_gbpages() -> bool {
        let edx: u32;
        // SAFETY: cpuid has no side effect; rbx is restored.
        unsafe {
            asm!("mov {t}, rbx", "cpuid", "mov rbx, {t}", t = out(reg) _,
                 inout("eax") 0x8000_0001u32 => _, inout("ecx") 0u32 => _, out("edx") edx,
                 options(nomem, nostack, preserves_flags));
        }
        edx & (1 << 26) != 0
    }

    /// CPUID.(7,0):ECX[16] (LA57).
    pub fn has_la57() -> bool {
        let ecx: u32;
        // SAFETY: as `has_gbpages`.
        unsafe {
            asm!("mov {t}, rbx", "cpuid", "mov rbx, {t}", t = out(reg) _,
                 inout("eax") 7u32 => _, inout("ecx") 0u32 => ecx, out("edx") _,
                 options(nomem, nostack, preserves_flags));
        }
        ecx & (1 << 16) != 0
    }

    /// `invlpg`: this CPU's entries for `va` in the current PCID, and its
    /// global entry for `va` if any.
    #[inline(always)]
    pub fn invlpg(va: usize) {
        // SAFETY: invalidation only.
        unsafe { asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags)) };
    }

    /// `invpcid kind, {pcid, addr}`. Only when [`invpcid_on`].
    #[inline(always)]
    pub fn invpcid(kind: u64, pcid: u16, addr: usize) {
        let desc: [u64; 2] = [pcid as u64, addr as u64];
        // SAFETY: invalidation only; the probe allowed the instruction.
        unsafe { asm!("invpcid {}, [{}]", in(reg) kind, in(reg) &desc, options(nostack, preserves_flags)) };
    }

    /// Drop every non-global entry of the current PCID (a CR3 reload with
    /// no-flush clear).
    #[inline]
    pub fn flush_current() {
        write_cr3(read_cr3() & !CR3_NOFLUSH);
    }

    /// Drop everything, global entries included.
    pub fn flush_all() {
        if invpcid_on() {
            invpcid(INVPCID_ALL_GLOBAL, 0, 0);
            return;
        }
        let cr4 = read_cr4();
        if cr4 & CR4_PGE != 0 {
            // Toggling PGE flushes every PCID, globals included.
            write_cr4(cr4 & !CR4_PGE);
            write_cr4(cr4);
        } else {
            // No PGE means no global entry. With PCIDE only the live PCID is
            // nameable; the others are dropped by their switch-in.
            flush_current();
        }
    }

    /// Drop the non-global entries tagged with `asid`'s PCID. Without
    /// `invpcid` only the live PCID can be named; another PCID's entries are
    /// unreachable until its switch-in, which drops them.
    pub fn flush_asid(asid: u16) {
        if !pcid_on() {
            flush_current();
        } else if invpcid_on() {
            invpcid(INVPCID_SINGLE, (asid as u64 & CR3_PCID_MASK) as u16, 0);
        } else if cr3_pcid(read_cr3()) == (asid as u64 & CR3_PCID_MASK) as u16 {
            flush_current();
        }
    }

    /// Paging setup on this CPU, after boot.S's long-mode entry: the depth
    /// (CR4.LA57 is boot.S's choice), the PAT, CR0.WP, CR4.PGE, and CR4.PCIDE
    /// when `caps.pcid`. EFER.NXE (boot.S) is read back, never set here: a
    /// leaf with NX and no NXE is a reserved-bit fault, so a clear NXE is
    /// reported for the caller to refuse the boot. Every CPU runs it.
    pub fn enable_paging(caps: &PagingCaps) -> PagingState {
        set_levels(if read_cr4() & CR4_LA57 != 0 { LEVELS_5 } else { LEVELS_4 });
        set_gbpages(caps.gbpages);
        // PAT before any PCD/PWT leaf is built, so index 3 is UC.
        wrmsr(IA32_PAT, PAT_VALUE);
        let cr0 = read_cr0();
        if cr0 & CR0_WP == 0 {
            write_cr0(cr0 | CR0_WP);
        }
        let mut cr4 = read_cr4() | CR4_PGE;
        // PCIDE may be set only with CR3[11:0] = 0 (#GP otherwise): boot.S's
        // root and every kernel root carry PCID 0.
        if caps.pcid && read_cr3() & CR3_PCID_MASK == 0 {
            cr4 |= CR4_PCIDE;
        }
        write_cr4(cr4);
        let cr4 = read_cr4();
        PCID_ON.store(cr4 & CR4_PCIDE != 0, Ordering::Relaxed);
        INVPCID_ON.store(caps.invpcid, Ordering::Relaxed);
        // The PAT change and PGE take effect for new walks; drop the rest.
        flush_all();
        state()
    }

    /// CR4.SMEP / CR4.SMAP when allowed (the `post_heap` step: every kernel
    /// access to user memory must already go through `UserAccess`).
    pub fn enable_access_protection(caps: &PagingCaps) -> PagingState {
        let mut cr4 = read_cr4();
        if caps.smep { cr4 |= CR4_SMEP; }
        if caps.smap { cr4 |= CR4_SMAP; }
        write_cr4(cr4);
        SMAP_ON.store(read_cr4() & CR4_SMAP != 0, Ordering::Relaxed);
        state()
    }

    /// The control-register readback.
    pub fn state() -> PagingState {
        let cr4 = read_cr4();
        PagingState {
            levels: levels(),
            nxe: rdmsr(IA32_EFER) & EFER_NXE != 0,
            wp: read_cr0() & CR0_WP != 0,
            pge: cr4 & CR4_PGE != 0,
            pcide: cr4 & CR4_PCIDE != 0,
            smep: cr4 & CR4_SMEP != 0,
            smap: cr4 & CR4_SMAP != 0,
            pat: rdmsr(IA32_PAT),
        }
    }

    /// `stac`: open the kernel's window onto user pages (SMAP).
    #[inline(always)]
    pub fn stac() {
        // SAFETY: sets RFLAGS.AC; only reached with CR4.SMAP set (the CPU has
        // the instruction). Not `preserves_flags`: it writes AC. Not `nomem`
        // either: it is the compiler barrier that keeps the user accesses
        // inside the window.
        unsafe { asm!("stac", options(nostack)) };
    }

    /// `clac`: close it.
    #[inline(always)]
    pub fn clac() {
        // SAFETY: clears RFLAGS.AC; as `stac` (a barrier too).
        unsafe { asm!("clac", options(nostack)) };
    }
}
