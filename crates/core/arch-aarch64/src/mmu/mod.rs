// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! VMSAv8-64 Stage-1 page-table entry encoding — level-aware, matching the
//! cross-ISA surface `azos_arch_api::Mmu` declares (page-table
//! abstraction, B2).
//!
//! The PTE format documented here is for a **3-level translation** whose
//! granule is a build-time choice ([`GRANULE`]; Kconfig `AARCH64_PAGE_4K` /
//! `_16K` / `_64K`). The default is the 4 KB granule (TG=0b00, T0SZ=25 →
//! 39-bit input range — the config `arch-aarch64::mmu::setup` programs at
//! boot, and the same input range as the RISC-V Sv39 this crate ports
//! alongside). Walk starts at L1: `L1 → L2 → L3`, three levels, 512 entries
//! each — this file's own earlier version said "4-level" here, which was
//! never true of what `mmu/setup.rs` boots; corrected alongside this module's
//! level-aware rewrite.
//!
//! The descriptor encoding is identical at the bit level for 16 KB and 64 KB
//! granules — only the index widths, the table size and the input range
//! differ, and [`Granule`] carries those. Output addresses this crate writes
//! are always granule-aligned, so the 4 KB output-address mask reads them
//! back unchanged (bits below the granule, and the LPA high-address fields at
//! `[15:12]`, are never set).
//!
//! # Trait level numbering
//!
//! `azos_arch_api::Mmu` numbers levels so `0` is the leaf level and
//! `LEVELS - 1` is the root, matching how `crates/core/mm` already walked Sv39.
//! On aarch64: trait level `0` = ARM `L3`, level `1` = ARM `L2`, level `2`
//! = ARM `L1` (the root). Every function below that takes a `level` takes
//! the TRAIT number.
//!
//! # Leaf vs. table: why `level` cannot be dropped
//!
//! Bits `[1:0]` mean different things depending on where in the tree a
//! word is read: `0b11` is a TABLE descriptor at L1/L2 (trait level 1, 2)
//! but a PAGE descriptor (a leaf) at L3 (trait level 0); `0b01` is a BLOCK
//! descriptor (a leaf) at L1/L2 and reserved/invalid at L3. A same-named
//! `is_leaf(word)` with no level parameter — the shape RISC-V Sv39 gets
//! away with, since leafness there depends only on R/W/X bits — would be
//! dishonest here.
//!
//! # Software bits
//!
//! Arm ARM §D8.3 reserves 4 bits at `[58:55]` for software use in a stage-1
//! descriptor; the hardware never reads them. This crate uses two:
//! `SW_COW` (bit 55, mm's fork-sharing marker — the same role RISC-V's RSW
//! bit 8 plays) and `SW_DIRTY` (bit 56, a software-tracked write marker;
//! aarch64 stage-1 has no hardware dirty-bit management wired up in this
//! tree, so "dirty" here is purely mm's bookkeeping, round-tripped through
//! [`perms_of`]/[`make_leaf`] the same way RISC-V's architectural D bit is).
//!
//! A DEMAND marker (mm's "reserved but not yet backed" state) sets `VALID =
//! 0`, which makes the MMU ignore every other bit in the word — so instead
//! of contending for one more software bit alongside COW/DIRTY, the marker
//! reuses the *entire* attribute encoding a real leaf would carry (AttrIdx,
//! AP, PXN/UXN, nG) so [`demand_perms`] can decode it with the same logic
//! [`perms_of`] uses, plus one more bit (58) that only means something
//! while invalid: "this hole is DEMAND-reserved" vs. "this hole is just
//! unmapped".

use azos_arch_api::{MemType, PagePerms, MmuError};

// The EL2 -> EL1 trampoline and the identity-map MMU enable. Bare-metal only:
// both program EL1/EL2 state, and `boot` carries ELF-section assembly. Host
// tests pull THIS file for the descriptor arithmetic below (`#[path]`, and
// `tests/host/arch-tests` among them), where neither could assemble.
#[cfg(target_os = "none")]
pub mod boot;
#[cfg(target_os = "none")]
pub mod setup;
// Virtual KASLR (Kconfig `KASLR`): the image window and the image base are
// pure and host-tested; the boot half (RNDRRS, the relocation walk) is
// bare-metal only.
pub mod kaslr;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub mod kaslr_boot;

/// Page size in bytes: the translation granule this build selected
/// (`azos_arch_api::PAGE_SIZE`; Kconfig `AARCH64_PAGE_*`).
pub const PAGE_SIZE: usize = azos_arch_api::PAGE_SIZE;

/// log2(PAGE_SIZE) — bits shifted off a VA / PA to get a page number.
pub const PAGE_SHIFT: usize = azos_arch_api::PAGE_SHIFT;

/// Levels in the walk: three on every granule this crate builds (see
/// [`Granule`] for the input-range sizes that keep it at three).
pub const LEVELS: usize = 3;

/// One VMSAv8-64 stage-1 translation regime: a granule plus the input range
/// (`T0SZ` / `T1SZ = 64 - va_bits`) chosen for it.
///
/// Every granule here walks exactly three levels, so `crates/core/mm`'s
/// three-level walk (trait levels 2, 1, 0) is unchanged:
///
/// | granule | va_bits | root (trait 2)        | trait 1 slot | trait 0 page |
/// |---------|---------|-----------------------|--------------|--------------|
/// | 4 KiB   | 39      | ARM L1, 512 × 1 GiB   | 2 MiB        | 4 KiB        |
/// | 16 KiB  | 39      | ARM L1, 8 × 64 GiB    | 32 MiB       | 16 KiB       |
/// | 64 KiB  | 48      | ARM L1, 64 × 4 TiB    | 512 MiB      | 64 KiB       |
///
/// 16 KiB keeps the 39-bit range (and so `KERNEL_VA_OFFSET` and the whole
/// virtual layout) of the 4 KiB build; its root has 8 live entries. 64 KiB
/// at 39 bits would walk two levels, so it takes 48 bits instead and its
/// upper half moves to `0xFFFF_0000_0000_0000`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Granule {
    /// log2 of the page size.
    pub page_shift: usize,
    /// Input-address bits (`64 - T0SZ`), same for TTBR0 and TTBR1.
    pub va_bits: usize,
}

/// 4 KiB granule, 39-bit input range — the default.
pub const GRANULE_4K: Granule = Granule { page_shift: 12, va_bits: 39 };
/// 16 KiB granule, 39-bit input range (8-entry root).
pub const GRANULE_16K: Granule = Granule { page_shift: 14, va_bits: 39 };
/// 64 KiB granule, 48-bit input range (64-entry root).
pub const GRANULE_64K: Granule = Granule { page_shift: 16, va_bits: 48 };

impl Granule {
    /// The granule for a page shift; panics (at compile time when used in a
    /// const) for one VMSAv8-64 does not have.
    #[inline(always)]
    pub const fn for_page_shift(shift: usize) -> Granule {
        match shift {
            12 => GRANULE_4K,
            14 => GRANULE_16K,
            16 => GRANULE_64K,
            _ => panic!("VMSAv8-64 granules are 4, 16 and 64 KiB"),
        }
    }
    /// Page size in bytes.
    #[inline(always)]
    pub const fn page_size(self) -> usize { 1 << self.page_shift }
    /// Index bits per table: a table is one page of 8-byte descriptors.
    #[inline(always)]
    pub const fn index_bits(self) -> usize { self.page_shift - 3 }
    /// Descriptors per table.
    #[inline(always)]
    pub const fn entries(self) -> usize { 1 << self.index_bits() }
    /// The VA bit a trait-`level` index starts at.
    #[inline(always)]
    pub const fn level_shift(self, level: usize) -> usize {
        self.page_shift + self.index_bits() * level
    }
    /// Bytes one entry at trait `level` maps (a page at 0, a block at 1).
    #[inline(always)]
    pub const fn level_size(self, level: usize) -> usize { 1 << self.level_shift(level) }
    /// Descriptors the root table indexes for this input range.
    #[inline(always)]
    pub const fn root_entries(self) -> usize {
        1 << (self.va_bits - self.level_shift(LEVELS - 1))
    }
    /// The index into the table at trait `level` that `va` selects. The root
    /// index is masked to the input range, so an upper-half (TTBR1) address
    /// selects the same slot as its low alias.
    #[inline(always)]
    pub const fn vpn(self, va: usize, level: usize) -> usize {
        let mask = if self.root_entries() == self.entries() || level != LEVELS - 1 {
            self.entries() - 1
        } else {
            self.root_entries() - 1
        };
        (va >> self.level_shift(level)) & mask
    }
    /// `TCR_EL1.T0SZ` / `T1SZ`.
    #[inline(always)]
    pub const fn tsz(self) -> u64 { (64 - self.va_bits) as u64 }
    /// `TCR_EL1.TG0` encoding (4 KiB `0b00`, 64 KiB `0b01`, 16 KiB `0b10`).
    #[inline(always)]
    pub const fn tg0(self) -> u64 {
        match self.page_shift { 12 => 0b00, 16 => 0b01, _ => 0b10 }
    }
    /// `TCR_EL1.TG1` encoding — NOT TG0's (16 KiB `0b01`, 4 KiB `0b10`,
    /// 64 KiB `0b11`; `0b00` is reserved).
    #[inline(always)]
    pub const fn tg1(self) -> u64 {
        match self.page_shift { 14 => 0b01, 12 => 0b10, _ => 0b11 }
    }
    /// The upper-half linear-map offset: every VA bit above the input range.
    #[inline(always)]
    pub const fn kernel_va_offset(self) -> u64 { !((1u64 << self.va_bits) - 1) }
    /// Pages one contiguous-hint run of level-3 descriptors spans (Arm ARM
    /// D8.6, "The Contiguous bit"): 16 at a 4 KiB granule (64 KiB), 128 at
    /// 16 KiB and 32 at 64 KiB (2 MiB both).
    #[inline(always)]
    pub const fn contig_pages(self) -> usize {
        match self.page_shift { 12 => 16, 14 => 128, _ => 32 }
    }
    /// Bytes of one contiguous-hint run.
    #[inline(always)]
    pub const fn contig_size(self) -> usize { self.contig_pages() * self.page_size() }
    /// Does `ID_AA64MMFR0_EL1` say this PE implements the granule for stage
    /// 1? `TGran4` `[31:28]` and `TGran64` `[27:24]` read `0b1111` when
    /// absent; `TGran16` `[23:20]` reads `0b0000` when absent.
    #[inline(always)]
    pub const fn supported_by(self, mmfr0: u64) -> bool {
        match self.page_shift {
            12 => (mmfr0 >> 28) & 0xF != 0xF,
            16 => (mmfr0 >> 24) & 0xF != 0xF,
            _ => (mmfr0 >> 20) & 0xF != 0,
        }
    }
}

/// The granule this build was configured for.
pub const GRANULE: Granule = Granule::for_page_shift(PAGE_SHIFT);

/// The bootstrap identity map's DRAM window: one gigabyte
/// (`mmu::setup::enable_identity_map`).
pub const BOOT_WINDOW: u64 = 1 << 30;

/// The gigabyte the bootstrap map makes Device, for a DRAM window at
/// `base_pa`: the one at PA 0 when DRAM starts at or above 1 GiB (QEMU
/// `virt`: the GIC, the PL011 and virtio-mmio sit below its RAM at 1 GiB),
/// else the one right after the DRAM window (a board whose RAM starts at 0,
/// the Raspberry Pi 3: its ARM-local interrupt controller is at 1 GiB). A
/// board's devices inside the DRAM gigabyte itself (the Pi's peripherals at
/// 0x3F00_0000, above the end of RAM) are made Device later, from the device
/// tree's `/memory` ([`boot_tail_blocks`]).
pub const fn boot_device_window(base_pa: u64) -> u64 {
    if base_pa >= BOOT_WINDOW { 0 } else { base_pa + BOOT_WINDOW }
}

/// The level-2 entries of the bootstrap map's DRAM window at `base_pa` (granule
/// `g`) that lie wholly in `[ram_end, base_pa + 1 GiB)`: the window's tail
/// past the end of RAM, which a board may use for devices. `(first index,
/// count)`, count 0 when RAM fills the window or a block is too large to
/// leave RAM out (64 KiB: 512 MiB blocks). A block that holds the end of RAM
/// stays Normal, and so does the first block (the level-3 table's: the image
/// is in it).
pub const fn boot_tail_blocks(g: Granule, base_pa: u64, ram_end: u64) -> (usize, usize) {
    let block = g.level_size(1) as u64;
    let blocks = (BOOT_WINDOW / block) as usize;
    let first = g.vpn(base_pa as usize, 1);
    if ram_end <= base_pa || ram_end >= base_pa + BOOT_WINDOW {
        return (first, 0);
    }
    let mut start = ((ram_end - base_pa + block - 1) / block) as usize;
    if start == 0 {
        start = 1;
    }
    if start >= blocks {
        return (first, 0);
    }
    (first + start, blocks - start)
}
const _: () = assert!(GRANULE.page_size() == PAGE_SIZE);

/// Pages in one contiguous-hint run at this build's granule.
pub const CONT_PAGES: usize = GRANULE.contig_pages();
/// Bytes in one contiguous-hint run: a power of two, and a divisor of the
/// span of one level-3 table, so a run never straddles two tables.
pub const CONT_SIZE: usize = GRANULE.contig_size();
const _: () = assert!(CONT_PAGES.is_power_of_two() && CONT_PAGES <= GRANULE.entries());

/// Entries per table (512 at 4 KiB, 2048 at 16 KiB, 8192 at 64 KiB).
pub const ENTRIES_PER_TABLE: usize = GRANULE.entries();

/// Round `addr` up to the next page boundary (inclusive of `addr`
/// when already aligned). Mirrors `arch-riscv64::mmu::page_align_up`
/// so kernel call sites can use the facade re-export unchanged.
pub const fn page_align_up(addr: usize) -> usize {
    (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// Round `addr` down to the start of its containing page.
pub const fn page_align_down(addr: usize) -> usize {
    addr & !(PAGE_SIZE - 1)
}

/// True iff `addr` is the start of a page.
pub const fn is_page_aligned(addr: usize) -> bool {
    addr & (PAGE_SIZE - 1) == 0
}

/// Index mask of a non-root table, and of the root (equal at 4 KiB).
const IDX_MASK: usize = GRANULE.entries() - 1;
const ROOT_MASK: usize = GRANULE.root_entries() - 1;
/// VA bits each level's index moves by (9 at 4 KiB).
const IDX_BITS: usize = GRANULE.index_bits();

/// The index into the table at trait `level` that `va` selects. At 4 KiB the
/// same VPN split as Sv39 — see the module doc and [`Granule::vpn`].
///
/// Written over plain constants rather than as a call to `GRANULE.vpn`: this
/// is `#[inline]` into `crates/core/mm`'s walks, and there the arithmetic must
/// fold to Sv39's `(va >> (12 + 9 * level)) & 0x1FF` — at 4 KiB the two masks
/// are the same constant, so the `level` test disappears even when `level` is
/// a loop variable.
#[inline]
pub const fn vpn(va: usize, level: usize) -> usize {
    let mask = if level == LEVELS - 1 { ROOT_MASK } else { IDX_MASK };
    (va >> (PAGE_SHIFT + IDX_BITS * level)) & mask
}
const _: () = assert!(vpn(0x7F_FFFF_F000, 2) == GRANULE.vpn(0x7F_FFFF_F000, 2));

// ── Raw bit layout (Arm ARM §D8.3) ──────────────────────────────────────

const VALID: u64 = 1 << 0;
/// Bit [1]: at a non-leaf level (trait level > 0), 1 = table descriptor,
/// 0 = block (leaf). At the leaf level (trait level 0), must be 1 for a
/// valid page descriptor — 0 there is reserved/invalid.
const TYPE_TABLE_OR_PAGE: u64 = 1 << 1;
const ATTRIDX_SHIFT: u32 = 2;
/// `AttrIdx` values as `mmu/setup.rs` actually programs `MAIR_EL1`
/// (`MAIR_VALUE = (0xFF << 8) | 0x04`): idx 0 = Device-nGnRE (`0x04`),
/// idx 1 = Normal WB Inner+Outer (`0xFF`).
///
/// **This module previously had the two swapped** (idx 0 = Normal, idx 1 =
/// Device) — a real encoding bug, harmless only because the old
/// `encode_pte` this file backed had no production caller. Fixed to match
/// `mmu/setup.rs`, which is what actually boots; `mmu/setup.rs` itself is
/// intentionally left alone.
///
/// **Single source since 2026-09-21.** The swap above was possible because
/// three places each held their own view of which index meant what: this
/// file's two constants, `mmu/setup.rs`'s `MAIR_VALUE` bytes, and the literal
/// `attr_idx(1)` / `attr_idx(0)` `mmu/setup.rs` builds the boot identity map
/// with. Now the index AND the attribute byte it selects live here, and
/// `mmu/setup.rs` imports both, so the index a leaf carries and the byte
/// `MAIR_EL1` holds at that index cannot disagree. `tests/host/arch-api-tests`
/// asserts the architectural meaning — a cacheable leaf selects Normal WB,
/// an uncached one Device-nGnRE — by reading `MAIR_VALUE` at the leaf's
/// own index.
pub const MAIR_IDX_DEVICE: u64 = 0;
pub const MAIR_IDX_NORMAL: u64 = 1;
/// `MemType::NC`: Normal memory, Inner+Outer Non-cacheable.
pub const MAIR_IDX_NORMAL_NC: u64 = 2;
/// `MemType::WC`: the same Normal Non-cacheable attribute under its own
/// index, so a decoded leaf tells `WC` from `NC` (Normal NC already allows
/// gathering and reordering, which is what write-combining needs).
pub const MAIR_IDX_NORMAL_WC: u64 = 3;
/// Device-nGnRE: non-Gathering, non-Reordering, Early write ack.
pub const MAIR_ATTR_DEVICE_NGNRE: u64 = 0x04;
/// Normal memory, Inner+Outer Write-Back non-transient, R+W allocate.
pub const MAIR_ATTR_NORMAL_WB: u64 = 0xFF;
/// Normal memory, Inner+Outer Non-cacheable.
pub const MAIR_ATTR_NORMAL_NC: u64 = 0x44;
/// The `MAIR_EL1` value `mmu/setup.rs` programs, derived from the pairs
/// above rather than written out a second time.
pub const MAIR_VALUE: u64 = (MAIR_ATTR_NORMAL_WB << (8 * MAIR_IDX_NORMAL))
    | (MAIR_ATTR_DEVICE_NGNRE << (8 * MAIR_IDX_DEVICE))
    | (MAIR_ATTR_NORMAL_NC << (8 * MAIR_IDX_NORMAL_NC))
    | (MAIR_ATTR_NORMAL_NC << (8 * MAIR_IDX_NORMAL_WC));
const ATTRIDX_DEVICE: u64 = MAIR_IDX_DEVICE << ATTRIDX_SHIFT;
const ATTRIDX_NORMAL: u64 = MAIR_IDX_NORMAL << ATTRIDX_SHIFT;
const ATTRIDX_NORMAL_NC: u64 = MAIR_IDX_NORMAL_NC << ATTRIDX_SHIFT;
const ATTRIDX_NORMAL_WC: u64 = MAIR_IDX_NORMAL_WC << ATTRIDX_SHIFT;
/// AP\[1\] (bit 6): 0 = EL1-only, 1 = EL0+EL1 (user-accessible).
const AP_EL0: u64 = 1 << 6;
/// AP\[2\] (bit 7): 0 = R/W, 1 = R/O.
const AP_RO: u64 = 1 << 7;
/// SH\[1:0\] = 0b11 (Inner Shareable) — Normal cacheable mappings on SMP
/// must be IS for coherence with other PEs.
const SH_INNER: u64 = 0b11 << 8;
/// AF — Access Flag.
pub const AF: u64 = 1 << 10;
/// nG — non-global.
const NG: u64 = 1 << 11;
/// Output-address bits `[47:12]` — same field for a table pointer or a
/// leaf frame base.
const OA_MASK: u64 = 0x0000_FFFF_FFFF_F000;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;
/// Software bit: mm's copy-on-write marker (see module doc).
const SW_COW: u64 = 1 << 55;
/// Software bit: mm's software-tracked dirty marker (see module doc).
const SW_DIRTY: u64 = 1 << 56;
/// Contiguous hint (bit 52): this level-3 page is one of a run of
/// [`CONT_PAGES`] adjacent pages the TLB may cache as one entry.
const CONT: u64 = 1 << 52;
/// Software bit: valid only while `VALID = 0` — marks a DEMAND-reserved
/// hole (see module doc).
const SW_DEMAND: u64 = 1 << 58;

/// The empty (all-zero) word — an unmapped slot.
#[inline]
pub const fn empty() -> u64 { 0 }

/// Is `word`'s valid bit set? True for both table and leaf entries.
#[inline]
pub const fn is_valid(word: u64) -> bool { word & VALID != 0 }

/// Is `word`, read AT `level` (trait numbering), a pointer to the
/// next-level table?
#[inline]
pub const fn is_table(word: u64, level: usize) -> bool {
    level > 0 && is_valid(word) && (word & TYPE_TABLE_OR_PAGE != 0)
}

/// Is `word`, read AT `level` (trait numbering), a leaf (page/block)?
#[inline]
pub const fn is_leaf(word: u64, level: usize) -> bool {
    if !is_valid(word) { return false; }
    if level == 0 {
        word & TYPE_TABLE_OR_PAGE != 0 // page descriptor at L3
    } else {
        word & TYPE_TABLE_OR_PAGE == 0 // block descriptor at L1/L2
    }
}

/// The physical address `word` encodes: the next-level table's base for a
/// table entry, or the mapped frame's base for a leaf.
#[inline]
pub const fn phys_addr(word: u64) -> usize {
    (word & OA_MASK) as usize
}

/// Build a non-leaf descriptor pointing at the table based at `pa`.
#[inline]
pub const fn make_table(pa: usize) -> u64 {
    ((pa as u64) & OA_MASK) | VALID | TYPE_TABLE_OR_PAGE
}

/// Encode the level-independent attribute bits `perms` implies (AttrIdx,
/// AP, PXN/UXN, nG — everything except `VALID`/the type bit/the physical
/// address). Shared by [`make_leaf`] and [`make_demand`], which store the
/// same attributes at `VALID = 0`.
///
/// AF is set unconditionally, matching this crate's existing convention
/// (`arch-aarch64::api_impl`'s original `encode_pte` always set AF too):
/// every leaf this tree ever creates requests `accessed`, so honoring the
/// field instead of hardcoding AF would not change any real caller's
/// output — see the `Mmu` trait doc in `crates/core/arch-api` for the general
/// rule this follows.
fn attr_bits(perms: PagePerms) -> Result<u64, MmuError> {
    if !perms.read {
        // No EL0/EL1-reachable "no read" encoding on VMSAv8 stage 1.
        return Err(MmuError::UnrepresentablePerms);
    }
    let mut attrs = AF | SH_INNER;
    attrs |= match perms.mem {
        MemType::WB => ATTRIDX_NORMAL,
        MemType::WC => ATTRIDX_NORMAL_WC,
        MemType::NC => ATTRIDX_NORMAL_NC,
        MemType::Device => ATTRIDX_DEVICE,
    };
    // AP[1] (EL0 reach) and AP[2] (read-only) are independent bits: AP=00
    // is EL1-only R/W, AP=01 is EL0+EL1 R/W, AP=10 is EL1-only R/O, AP=11
    // is EL0+EL1 R/O.
    if perms.user {
        attrs |= AP_EL0;
        // M38/U10-3 (audit + coordinator): EL1 must never be able to
        // EXECUTE a page EL0 can reach, independent of whether EL0 itself
        // may execute it. This used to be `if !perms.exec { attrs |= PXN
        // ... }` only — a user RX page (read+exec, no write: the common
        // case for a ring-3 `.text` mapping) had NEITHER PXN nor UXN, so
        // EL1 could fetch and execute straight out of it (ret2usr: a
        // kernel bug that redirects PC into attacker-controlled user
        // memory runs there instead of faulting). RISC-V forbids this
        // architecturally (S-mode can never execute a `U=1` page,
        // regardless of any control bit) — this closes the same hole on
        // aarch64 by software policy instead of hardware guarantee.
        attrs |= PXN;
    }
    if !perms.write {
        attrs |= AP_RO;
    }
    if !perms.exec {
        attrs |= PXN;
        if perms.user {
            attrs |= UXN;
        }
    }
    if !perms.user {
        // Kernel-only leaves are NEVER executable at EL0, including kernel
        // text. AP[1] = 0 does not forbid EL0 instruction fetch on VMSAv8-64:
        // AP = 00 with UXN = 0 is the architectural "EL0 execute-only"
        // encoding (Linux's PAGE_EXECONLY; FEAT_EPAN exists because of it).
        // Without this bit EL0 could branch into and run kernel text (found
        // wave 4: an O3.1 race returned to EL0 at a kernel address and the
        // CPU executed `msr SPSR_EL1` there, EC=0, instead of taking an
        // instruction abort). Linux's PROT_NORMAL carries PTE_UXN for the
        // same reason. `perms_from_attr_bits` reads a kernel leaf's exec
        // from PXN, so this changes no decoded permission.
        attrs |= UXN;
    }
    if perms.user {
        attrs |= NG;
    }
    if perms.dirty {
        attrs |= SW_DIRTY;
    }
    Ok(attrs)
}

/// GP (bit 50): FEAT_BTI guarded page. [`attr_bits`] never sets it.
const GP: u64 = 1 << 50;

/// Whether ring 3's text is mapped as BTI guarded pages (the GP bit on a
/// [`PagePerms::USER_RX`] leaf): the condition under which a `bti` landing
/// pad is enforced at EL0. The vDSO's `HWCAP_A64_BTI` is gated on it.
pub fn user_text_is_guarded() -> bool {
    matches!(attr_bits(PagePerms::USER_RX), Ok(a) if a & GP != 0)
}

/// Whether [`MAIR_VALUE`] holds a Normal-Tagged attribute (`0xF0`), the
/// memory type MTE tag checks apply to. The vDSO's `HWCAP_A64_MTE` is
/// gated on it.
pub const fn mair_has_tagged_normal() -> bool {
    let mut i = 0;
    while i < 8 {
        if (MAIR_VALUE >> (8 * i)) & 0xFF == 0xF0 {
            return true;
        }
        i += 1;
    }
    false
}

/// Decode the attribute bits [`attr_bits`] encodes, back into [`PagePerms`].
/// Level-independent: attribute bits live in the same positions regardless
/// of whether the word is a page (L3) or block (L1/L2) descriptor.
fn perms_from_attr_bits(word: u64) -> PagePerms {
    let user = word & AP_EL0 != 0;
    let ro = word & AP_RO != 0;
    // M38/U10-3: `attr_bits` now sets PXN unconditionally on every user
    // page (EL1 must never execute a page EL0 can reach — the ret2usr
    // hardening), so PXN alone no longer tells us whether the ORIGINAL
    // `perms.exec` request was true or false for a user page. UXN still
    // does: for a user page `attr_bits` only sets UXN when `!exec`. For a
    // kernel-only page (`!user`) UXN is always set, so PXN is
    // still the right (and only) signal there — exactly the pre-existing
    // behavior (kernel-only leaves now ALWAYS carry UXN — see `attr_bits` —
    // which is exactly why their exec must come from PXN). Getting this wrong silently strips `exec` off every user
    // page on decode → re-encode round trip (COW resolution, permission
    // widening, W^X re-checks), which would make a legitimately
    // executable user text page non-executable the first time its PTE is
    // read back and rewritten.
    let exec = if user { word & UXN == 0 } else { word & PXN == 0 };
    PagePerms {
        read: true,
        write: !ro,
        exec,
        user,
        mem: match (word >> ATTRIDX_SHIFT) & 0b111 {
            MAIR_IDX_NORMAL => MemType::WB,
            MAIR_IDX_NORMAL_NC => MemType::NC,
            MAIR_IDX_NORMAL_WC => MemType::WC,
            _ => MemType::Device,
        },
        accessed: word & AF != 0,
        dirty: word & SW_DIRTY != 0,
    }
}

/// Build a fresh leaf descriptor for `pa`, valid when read AT `level`
/// (trait numbering), carrying `perms`.
#[inline]
pub fn make_leaf(pa: usize, perms: PagePerms, level: usize) -> Result<u64, MmuError> {
    if pa & (PAGE_SIZE - 1) != 0 {
        return Err(MmuError::NotAligned);
    }
    let attrs = attr_bits(perms)?;
    let type_bit = if level == 0 { TYPE_TABLE_OR_PAGE } else { 0 };
    Ok(((pa as u64) & OA_MASK) | VALID | type_bit | attrs)
}

/// Build member `index` of the contiguous run whose first frame is `run_pa`:
/// a level-3 page descriptor for `run_pa + index * PAGE_SIZE` with the hint
/// bit. Every member of a run carries the same attributes (`perms`); `run_pa`
/// must be aligned to [`CONT_SIZE`], the virtual base the same (the caller
/// plans it, `azos_arch_api::contig`).
#[inline]
pub fn make_contig_leaf(run_pa: usize, index: usize, perms: PagePerms) -> Result<u64, MmuError> {
    if run_pa & (CONT_SIZE - 1) != 0 || index >= CONT_PAGES {
        return Err(MmuError::NotAligned);
    }
    Ok(make_leaf(run_pa + index * PAGE_SIZE, perms, 0)? | CONT)
}

/// Is `word` a valid descriptor carrying the contiguous hint?
#[inline]
pub const fn is_contig(word: u64) -> bool {
    word & (VALID | CONT) == VALID | CONT
}

/// `word` without the hint: the same frame and attributes as a lone page.
#[inline]
pub const fn clear_contig(word: u64) -> u64 {
    word & !CONT
}

/// Decode a leaf word's permissions.
#[inline]
pub fn perms_of(word: u64) -> PagePerms {
    perms_from_attr_bits(word)
}

/// Is `word` valid with the software COW bit set? A page marker's kind field
/// overlaps that bit (55), so a word that is not valid is never COW.
#[inline]
pub const fn is_cow(word: u64) -> bool { is_valid(word) && word & SW_COW != 0 }

/// Mark a writable leaf as COW-shared: clear the write permission (AP_RO),
/// set the software COW marker.
#[inline]
pub const fn share_cow(word: u64) -> u64 {
    word | AP_RO | SW_COW
}

/// Break a COW-shared leaf: clear the COW marker, clear AP_RO (restore
/// write), set the software dirty marker (the page was just written by
/// the copy that precedes this call).
#[inline]
pub const fn break_cow(word: u64) -> u64 {
    (word & !SW_COW & !AP_RO) | SW_DIRTY
}

/// Build a demand-paging marker: `VALID = 0` (any access traps), the
/// software DEMAND marker set, `perms`' attribute bits stored inline so
/// [`demand_perms`] can recover them when the fault fires.
#[inline]
pub fn make_demand(perms: PagePerms) -> Result<u64, MmuError> {
    Ok(attr_bits(perms)? | SW_DEMAND)
}

/// Is `word` a demand-paging marker (invalid, DEMAND-marked)?
#[inline]
pub const fn is_demand(word: u64) -> bool {
    !is_valid(word) && word & SW_DEMAND != 0
}

// ── Page markers (arch-api `PageMarker`) ──────────────────────────────────
//
// A not-present word is ignored whole by the walker (VALID = 0), so the
// marker is: software bit 57 (the one of the four at [58:55] that COW (55),
// DIRTY (56) and DEMAND (58) leave free) as the flag, DEMAND clear, the
// two-bit kind code in bits 56:55 (the COW/DIRTY positions, which only a
// valid leaf uses) and the 32-bit payload in the output-address field,
// bits 47:16.

/// The marker flag: software bit 57.
const SW_MARKER: u64 = 1 << 57;
const MARKER_KIND_SHIFT: u32 = 55;
const MARKER_PAYLOAD_SHIFT: u32 = 16;

/// A page marker of kind `code` (1..=3, `PageMarker::code`) carrying `payload`.
#[inline]
pub const fn make_marker(code: u8, payload: u32) -> u64 {
    SW_MARKER | (((code & 3) as u64) << MARKER_KIND_SHIFT) | ((payload as u64) << MARKER_PAYLOAD_SHIFT)
}

/// `(code, payload)` of a page marker; `None` for any other word.
#[inline]
pub const fn marker_of(word: u64) -> Option<(u8, u32)> {
    if word & (VALID | SW_DEMAND | SW_MARKER) != SW_MARKER {
        return None;
    }
    let code = ((word >> MARKER_KIND_SHIFT) & 3) as u8;
    if code == 0 {
        return None;
    }
    Some((code, (word >> MARKER_PAYLOAD_SHIFT) as u32))
}

/// Recover the perms stored in a demand marker built by [`make_demand`].
#[inline]
pub fn demand_perms(word: u64) -> PagePerms {
    perms_from_attr_bits(word)
}

// ─────────────────────────────────────────────────────────────────────────
// TTBR1_EL1 / TCR_EL1 upper-half fields — aarch64 parity program's
// "move the kernel into TTBR1" migration.
//
// **Scope of this wave.** This wave lands the TCR/TTBR1 encoding and a
// standalone alias table (`mmu::setup::enable_ttbr1_alias`) proving that
// encoding boots and resolves correctly — it does NOT yet move the
// kernel's own execution, `crates/core/mm`'s kernel page table, or any user
// page table onto this split (see that function's doc for exactly what
// is and is not wired up, and the task's own final report for what a
// later wave still has to do: link the kernel high, jump to it in
// boot.S, point `crates/core/mm`'s real kernel table here instead of TTBR0,
// and stop copying kernel entries into user tables).
// ─────────────────────────────────────────────────────────────────────────

/// Linear-map offset for the kernel's upper half: bits `[63:39]` all set,
/// matching `T1SZ = 25` (a 39-bit TTBR1 input range — the same width as
/// TTBR0's own `T0SZ = 25` in `mmu::setup::TCR_VALUE`, so both halves cover
/// the same span). Any VA with these top bits set walks through TTBR1;
/// everything else walks through TTBR0. `phys_to_virt(pa) = pa |
/// KERNEL_VA_OFFSET`, and the inverse masks it back off — matching the
/// Linux arm64 `PAGE_OFFSET` idiom (a fixed OR/AND, not a subtract): a
/// physical address is never already "high", so OR is exact, and masking
/// is idempotent on an address that is already a valid low PA.
pub const KERNEL_VA_OFFSET: u64 = GRANULE.kernel_va_offset();
const _: () = assert!(
    PAGE_SHIFT != 12 || KERNEL_VA_OFFSET == 0xFFFF_FF80_0000_0000,
    "the 4 KiB build's upper half must stay where kernel/linker-aarch64.ld links it",
);

/// `TCR_EL1.T1SZ` field position — mirrors `T0SZ` at bits `[5:0]`.
const TCR_T1SZ_SHIFT: u64 = 16;
const TCR_T1SZ_MASK: u64 = 0x3F << TCR_T1SZ_SHIFT;
/// `TCR_EL1.EPD1` (bit 23) — 0 enables TTBR1 walks, 1 disables them.
/// `mmu::setup::TCR_VALUE` sets this to 1 (TTBR1 unused) at boot;
/// `enable_ttbr1_alias` clears it — the one bit that turns TTBR1 live.
pub const TCR_EPD1: u64 = 1 << 23;
const TCR_IRGN1_SHIFT: u64 = 24;
const TCR_ORGN1_SHIFT: u64 = 26;
const TCR_SH1_SHIFT: u64 = 28;
const TCR_TG1_SHIFT: u64 = 30;

/// The TTBR1 sibling of `mmu::setup::TCR_VALUE`'s T0SZ/IRGN0/ORGN0/SH0/TG0
/// bits: same values, upper-half field positions. OR this into a LIVE
/// `TCR_EL1` read — never write it standalone, which would clobber T0SZ
/// and every other lower-half field TTBR0 still needs.
///
/// **`TG1`'s encoding is not `TG0`'s.** `TG0 = 0b00` means 4 KiB, but
/// `TG1 = 0b00` is RESERVED — 4 KiB under `TG1` is `0b10` (Arm ARM
/// §D8.2.10, `TCR_EL1.TG1`). Reusing `TG0`'s encoding here would silently
/// select an undefined granule instead of failing to build; canary (a)
/// (swap `0b10` for `0b00`) below is what proves this distinction is
/// load-bearing rather than a comment no test reads.
pub const TCR_TTBR1_BITS: u64 = (GRANULE.tsz() << TCR_T1SZ_SHIFT) // T1SZ = 25 at 4/16 KiB
    | (0b01 << TCR_IRGN1_SHIFT)                             // IRGN1  Normal WB inner
    | (0b01 << TCR_ORGN1_SHIFT)                              // ORGN1  Normal WB outer
    | (0b11 << TCR_SH1_SHIFT)                                 // SH1    Inner shareable
    | (GRANULE.tg1() << TCR_TG1_SHIFT);                        // TG1    4 KiB = 0b10 (NOT TG0's 0b00)

/// `TCR_EL1.E0PD1` (FEAT_E0PD, bit 56; bit 55 is `E0PD0`, the TTBR0 half,
/// which EL0 must keep using). Set: an EL0 access to the TTBR1 (kernel)
/// half faults at once, without a walk, so its latency does not tell
/// whether the address is mapped (Kconfig `A64_E0PD`).
pub const TCR_E0PD1: u64 = 1 << 56;

/// `tcr` with `E0PD1` set (`on`) or clear, every other bit as it was. Pure:
/// the boot's decision is `A64_E0PD`'s gate over ID_AA64MMFR2_EL1.E0PD.
#[inline]
pub const fn tcr_with_e0pd1(tcr: u64, on: bool) -> u64 {
    if on { tcr | TCR_E0PD1 } else { tcr & !TCR_E0PD1 }
}

/// `TCR_EL1.E0PD1` of a live register read.
#[inline]
pub const fn tcr_e0pd1(tcr: u64) -> bool {
    tcr & TCR_E0PD1 != 0
}

/// `TCR_EL1.HA` (FEAT_HAFDBS, bit 39): the PE sets AF itself when it
/// translates through a descriptor that has it clear, instead of taking an
/// Access Flag fault (Kconfig `A64_HAFDBS`). RES0 without FEAT_HAFDBS.
///
/// `TCR_EL1.HD` (bit 40, hardware dirty state) is left off: it only acts on a
/// descriptor with the DBM bit (51) set, which no leaf of this tree carries,
/// and a leaf that did would have the hardware clear AP[2] on the first write,
/// which is the write-protect `pte_share_cow` puts on a COW page. When a user
/// of dirty-state tracking appears, it brings its own switch.
pub const TCR_HA: u64 = 1 << 39;

/// `tcr` with `HA` set, every other bit as it was. Pure: the boot's decision
/// is `A64_HAFDBS`'s gate over ID_AA64MMFR1_EL1.HAFDBS.
#[inline]
pub const fn tcr_with_ha(tcr: u64) -> u64 {
    tcr | TCR_HA
}

/// `TCR_EL1.HA` of a live register read.
#[inline]
pub const fn tcr_ha(tcr: u64) -> bool {
    tcr & TCR_HA != 0
}

/// Extract `TCR_EL1.T0SZ` (bits `[5:0]`) from a live register read — read
/// back what the hardware actually latched, not the constant that asked
/// for it.
#[inline]
pub const fn tcr_t0sz(tcr: u64) -> u64 {
    tcr & 0x3F
}

/// Extract `TCR_EL1.T1SZ` (bits `[21:16]`).
#[inline]
pub const fn tcr_t1sz(tcr: u64) -> u64 {
    (tcr & TCR_T1SZ_MASK) >> TCR_T1SZ_SHIFT
}

/// Extract `TCR_EL1.IPS` (bits `[34:32]`) from a live register read. M41
/// (coordinator / U10-7, audit): a boot marker reads this back to prove the
/// value programmed is what `ID_AA64MMFR0_EL1.PARange` actually reported
/// (clamped — see `mmu::setup::ips_field`'s doc), not the `0` (32-bit PAs
/// only) it used to be unconditionally.
#[inline]
pub const fn tcr_ips(tcr: u64) -> u64 {
    (tcr >> 32) & 0x7
}

/// Extract `TCR_EL1.AS` (bit `36`) from a live register read — 0 = 8-bit
/// ASID, 1 = 16-bit. M41: this crate now always requests 1; the readback is
/// what a boot marker proves actually landed (see `mmu::setup::TCR_AS`'s
/// doc for why a hardware-RES0 implementation makes this a safe, if
/// sometimes silently-ignored, request).
#[inline]
pub const fn tcr_as(tcr: u64) -> u64 {
    (tcr >> 36) & 0x1
}

// M38/U10-3: host-runnable regression tests for the ret2usr fix (PXN
// unconditional on every user page) and the decode fix it required
// (UXN, not PXN, carries "software asked for exec" once `user` is true).
// Nothing in this file is `cfg(target_arch = "aarch64")`-gated — pure bit
// arithmetic, host-runnable in principle — but `cargo test` FROM THIS
// WORKSPACE cannot reach it: the workspace's own `.cargo/config.toml` forces
// `[unstable] build-std = ["core", "alloc"]` for every invocation (needed
// for the `riscv64imac`/aarch64-none embedded targets), and that rebuilds
// `core` from source even for a host target, which then collides with the
// sysroot's own prebuilt `core` the moment any dependency (here,
// `azos_arch_api`) does NOT also opt into build-std — a duplicate
// lang-item error, not a test failure, and pre-existing/out of this crate's
// scope to fix (workspace-wide config, shared by every crate). This is
// EXACTLY why `tests/host/arch-tests` exists (see its own module doc): excluded
// from the workspace, its own `.cargo/config.toml` sets `build-std = []`,
// and it `#[path]`-pulls this file in as `aarch64_mmu` specifically so
// these tests run for real, under `tools/ci_check.sh`'s host-test stage
// (`test_host "arch-tests" ...`). Run directly with
// `cd tests/host/arch-tests && cargo test --release aarch64_mmu::tests`.
#[cfg(test)]
mod tests {
    use super::*;

    /// A user RX page (the common case: a ring-3 `.text` mapping) must set
    /// PXN — EL1 must never execute a page EL0 can reach — while still
    /// decoding back to `exec: true`, since EL0 itself may still run it.
    #[test]
    fn user_rx_sets_pxn_but_decodes_executable() {
        let word = make_leaf(0x4000_0000, PagePerms::USER_RX, 0).unwrap();
        assert_ne!(word & PXN, 0, "user RX page must set PXN (ret2usr hardening)");
        assert_eq!(word & UXN, 0, "user RX page must NOT set UXN — EL0 may execute it");
        let decoded = perms_of(word);
        assert!(decoded.exec, "decode must still report exec=true for a user RX page");
        assert!(decoded.user);
        assert!(!decoded.write);
    }

    /// A user RW (non-exec) page must set BOTH PXN and UXN, and decode
    /// back to `exec: false`.
    #[test]
    fn user_rw_sets_pxn_and_uxn_decodes_non_executable() {
        let word = make_leaf(0x4000_0000, PagePerms::USER_RW, 0).unwrap();
        assert_ne!(word & PXN, 0, "user RW page must set PXN");
        assert_ne!(word & UXN, 0, "user RW page must set UXN — EL0 must not execute it");
        let decoded = perms_of(word);
        assert!(!decoded.exec);
        assert!(decoded.user);
        assert!(decoded.write);
    }

    /// Kernel-only pages: PXN alone tracks `exec`, and UXN is ALWAYS set.
    /// This test used to assert UXN clear ("EL0 cannot reach them
    /// regardless") — false: AP = 00 with UXN = 0 is VMSAv8-64's EL0
    /// execute-only encoding, so kernel text was executable from EL0.
    #[test]
    fn kernel_only_pages_are_never_el0_executable() {
        let rx = make_leaf(0x4000_0000, PagePerms::KERNEL_RX, 0).unwrap();
        assert_eq!(rx & PXN, 0, "kernel RX page must not set PXN");
        assert_ne!(rx & UXN, 0, "kernel RX page must set UXN — EL0 must never execute kernel text");
        assert!(perms_of(rx).exec);

        let rw = make_leaf(0x4000_0000, PagePerms::KERNEL_RW, 0).unwrap();
        assert_ne!(rw & PXN, 0, "kernel RW (non-exec) page must set PXN");
        assert!(!perms_of(rw).exec);
    }

    /// Full round trip for every named `PagePerms` constant this crate's
    /// own `arch-api-tests` distinguishes: `make_leaf` then `perms_of`
    /// must reproduce every field the encoding claims to carry (`read` is
    /// always true — VMSAv8 stage 1 has no "no read" encoding, matching
    /// `attr_bits`'s own `UnrepresentablePerms` check on `!perms.read`).
    #[test]
    fn round_trip_every_named_perm() {
        for p in [
            PagePerms::KERNEL_RW, PagePerms::KERNEL_RX, PagePerms::KERNEL_RO,
            PagePerms::KERNEL_RWX, PagePerms::USER_RW, PagePerms::USER_RX,
            PagePerms::USER_RO, PagePerms::MMIO,
        ] {
            let word = make_leaf(0x4000_1000, p, 0).unwrap();
            let back = perms_of(word);
            assert_eq!(back.read, p.read);
            assert_eq!(back.write, p.write);
            assert_eq!(back.exec, p.exec, "exec mismatch for {:?}", p);
            assert_eq!(back.user, p.user);
        }
    }

    /// `E0PD1` is bit 56 (bit 55 is `E0PD0`, TTBR0, which EL0 needs): setting
    /// it changes that bit only, clearing it undoes exactly that, and the
    /// readback finds it.
    #[test]
    fn tcr_e0pd1_is_bit_56_and_touches_nothing_else() {
        assert_eq!(TCR_E0PD1, 1u64 << 56);
        let tcr = TCR_TTBR1_BITS | 25 | (1 << 36);
        let on = tcr_with_e0pd1(tcr, true);
        assert_eq!(on ^ tcr, 1 << 56);
        assert!(tcr_e0pd1(on) && !tcr_e0pd1(tcr));
        assert_eq!(on & (1 << 55), 0, "E0PD0 must stay clear");
        assert_eq!(tcr_with_e0pd1(on, false), tcr);
        assert_eq!(tcr_with_e0pd1(on, true), on, "idempotent");
        assert_eq!(tcr_with_e0pd1(u64::MAX, false), u64::MAX & !(1 << 56));
    }

    /// The boot's whole decision: E0PD1 is set exactly when the Kconfig policy
    /// allows it and the ID register has the feature.
    #[test]
    fn e0pd1_is_set_only_when_the_policy_and_the_cpu_agree() {
        use azos_arch_api::isa::ExtPolicy;
        for (policy, present, want) in [
            (ExtPolicy::Never, true, false), (ExtPolicy::Never, false, false),
            (ExtPolicy::Probe, true, true), (ExtPolicy::Probe, false, false),
            (ExtPolicy::Require, true, true),
        ] {
            let tcr = tcr_with_e0pd1(TCR_TTBR1_BITS, policy.gate(present));
            assert_eq!(tcr_e0pd1(tcr), want, "{policy:?} present={present}");
        }
    }
}
