// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Stage-2 translation (IPA to PA) for a guest: the `VTCR_EL2` / `VTTBR_EL2`
//! values, the stage-2 descriptor encoder, and a table mapper over the frames
//! of a `MemObj`. Pure: no instruction is here, so the host tests
//! (`tests/host/arch-tests`) run all of it.
//!
//! Stage 2 always uses the 4 KiB granule, whatever granule the kernel's own
//! stage 1 runs (`PAGE_SHIFT`): a guest's view of memory does not follow the
//! host's page size, and a host frame of 16 or 64 KiB is simply 4 or 16
//! consecutive stage-2 pages ([`Stage2::map_frames`]).
//!
//! The IPA size picks the start level and the number of concatenated root
//! tables, as the VMSAv8-64 rules for a 4 KiB granule (without FEAT_LPA2):
//! up to 34 bits start at level 2 (at most 16 tables), up to 43 bits at
//! level 1 (at most 16), up to 48 bits at level 0 (one). 40 bits, the usual
//! guest, is level 1 with two tables: an 8 KiB root aligned to 8 KiB.
//!
//! Nothing here turns stage 2 on (`HCR_EL2.VM` is the run loop's); the values
//! are built, written to `VTCR_EL2` / `VTTBR_EL2` and enabled together by
//! whoever enters a guest.

/// Stage-2 page size (the 4 KiB granule).
pub const S2_PAGE: u64 = 4096;
/// Descriptors per 4 KiB table.
pub const S2_ENTRIES: u64 = 512;
/// Smallest and largest IPA width [`VtcrConfig::new`] accepts.
pub const IPA_BITS_MIN: u8 = 32;
/// See [`IPA_BITS_MIN`]; 52 bits would need FEAT_LPA2.
pub const IPA_BITS_MAX: u8 = 48;

/// Output-address bits `[47:12]` of a descriptor (no FEAT_LPA).
const ADDR_MASK: u64 = ((1u64 << 48) - 1) & !(S2_PAGE - 1);
const D_VALID: u64 = 1 << 0;
/// Bit 1: table at levels 0-2 and page at level 3 when set, block when clear.
const D_TABLE_OR_PAGE: u64 = 1 << 1;
const D_MEMATTR_SHIFT: u32 = 2;
const D_S2AP_SHIFT: u32 = 6;
const D_SH_SHIFT: u32 = 8;
const D_AF: u64 = 1 << 10;
/// XN[1] (bit 54), the stage-2 execute-never bit without FEAT_XNX.
const D_XN: u64 = 1 << 54;

/// `SH` field: inner shareable, for Normal memory.
const SH_INNER: u64 = 0b11;

/// Why a stage-2 operation refused.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum S2Error {
    /// An IPA width outside `IPA_BITS_MIN..=IPA_BITS_MAX`, or beyond the
    /// output size the CPU supports.
    BadIpaBits,
    /// `ID_AA64MMFR0_EL1.PARange` names no size this code knows.
    BadParange,
    /// A VMID wider than the 8 bits `VTCR_EL2.VS = 0` allows.
    VmidTooWide,
    /// An address not aligned to its table, block or page.
    Misaligned,
    /// A physical address of 2^48 or more.
    PaTooWide,
    /// An IPA outside the configured input size.
    IpaOutOfRange,
    /// A leaf level other than 1 (1 GiB), 2 (2 MiB) or 3 (4 KiB).
    BadLevel,
    /// Execute permission without read.
    ExecWithoutRead,
    /// The target is already mapped (or inside a block that is).
    Overlap,
    /// The target is not mapped.
    NotMapped,
    /// The table allocator is out of frames.
    NoMemory,
}

/// Memory type of a stage-2 mapping (`MemAttr[3:0]`, without FEAT_S2FWB):
/// the result combines with the guest's own stage-1 attribute, the more
/// restrictive of the two winning.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MemType {
    /// Device-nGnRnE.
    Device,
    /// Device-nGnRE: the guest's MMIO window.
    DeviceNgnre,
    /// Normal, inner and outer non-cacheable.
    NormalNc,
    /// Normal, inner and outer write-through.
    NormalWt,
    /// Normal, inner and outer write-back: guest RAM.
    NormalWb,
}

impl MemType {
    const fn memattr(self) -> u64 {
        match self {
            MemType::Device => 0b0000,
            MemType::DeviceNgnre => 0b0001,
            MemType::NormalNc => 0b0101,
            MemType::NormalWt => 0b1010,
            MemType::NormalWb => 0b1111,
        }
    }

    const fn from_memattr(v: u64) -> Option<MemType> {
        Some(match v {
            0b0000 => MemType::Device,
            0b0001 => MemType::DeviceNgnre,
            0b0101 => MemType::NormalNc,
            0b1010 => MemType::NormalWt,
            0b1111 => MemType::NormalWb,
            _ => return None,
        })
    }

    const fn is_device(self) -> bool {
        matches!(self, MemType::Device | MemType::DeviceNgnre)
    }
}

/// Permissions and memory type of one stage-2 leaf (`S2AP` and `XN`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct S2Attrs {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    pub mem: MemType,
}

impl S2Attrs {
    /// Guest RAM: read, write, execute, write-back.
    pub const RAM: S2Attrs = S2Attrs { read: true, write: true, exec: true, mem: MemType::NormalWb };
    /// Guest read-only memory (a ROM, a CoW source): read, execute.
    pub const ROM: S2Attrs = S2Attrs { read: true, write: false, exec: true, mem: MemType::NormalWb };
    /// A device window passed through: read and write, never executed.
    pub const MMIO: S2Attrs = S2Attrs { read: true, write: true, exec: false, mem: MemType::DeviceNgnre };
}

/// Bytes covered by one leaf at `level` (4 KiB granule).
pub const fn level_size(level: u8) -> u64 {
    1u64 << (12 + 9 * (3 - level as u32))
}

/// The leaf descriptor for `pa` at `level` (3: page, 2: 2 MiB block, 1:
/// 1 GiB block). AF is always set: nothing here takes access-flag faults.
pub const fn leaf_desc(pa: u64, level: u8, a: S2Attrs) -> Result<u64, S2Error> {
    if level < 1 || level > 3 {
        return Err(S2Error::BadLevel);
    }
    if pa >> 48 != 0 {
        return Err(S2Error::PaTooWide);
    }
    if pa & (level_size(level) - 1) != 0 {
        return Err(S2Error::Misaligned);
    }
    if a.exec && !a.read {
        return Err(S2Error::ExecWithoutRead);
    }
    let s2ap = (a.read as u64) | ((a.write as u64) << 1);
    let sh = if a.mem.is_device() { 0 } else { SH_INNER };
    let mut d = D_VALID | (pa & ADDR_MASK) | D_AF
        | (a.mem.memattr() << D_MEMATTR_SHIFT)
        | (s2ap << D_S2AP_SHIFT)
        | (sh << D_SH_SHIFT);
    if level == 3 {
        d |= D_TABLE_OR_PAGE;
    }
    if !a.exec {
        d |= D_XN;
    }
    Ok(d)
}

/// The table descriptor pointing at the 4 KiB-aligned next-level table.
pub const fn table_desc(next_pa: u64) -> Result<u64, S2Error> {
    if next_pa >> 48 != 0 {
        return Err(S2Error::PaTooWide);
    }
    if next_pa & (S2_PAGE - 1) != 0 {
        return Err(S2Error::Misaligned);
    }
    Ok(D_VALID | D_TABLE_OR_PAGE | (next_pa & ADDR_MASK))
}

/// Descriptor bit 0.
pub const fn desc_valid(d: u64) -> bool {
    d & D_VALID != 0
}

/// Descriptor is a table pointer at `level` (0-2); at level 3 bit 1 means page.
pub const fn desc_is_table(d: u64, level: u8) -> bool {
    level < 3 && d & (D_VALID | D_TABLE_OR_PAGE) == (D_VALID | D_TABLE_OR_PAGE)
}

/// Output address of a valid descriptor.
pub const fn desc_pa(d: u64) -> u64 {
    d & ADDR_MASK
}

/// Decode a leaf descriptor's permissions and memory type; `None` for a
/// memory type this encoder does not produce.
pub const fn leaf_attrs(d: u64) -> Option<S2Attrs> {
    let mem = match MemType::from_memattr((d >> D_MEMATTR_SHIFT) & 0xF) {
        Some(m) => m,
        None => return None,
    };
    let s2ap = (d >> D_S2AP_SHIFT) & 0b11;
    Some(S2Attrs { read: s2ap & 1 != 0, write: s2ap & 2 != 0, exec: d & D_XN == 0, mem })
}

/// Output sizes `ID_AA64MMFR0_EL1.PARange` and `VTCR_EL2.PS` name.
const PARANGE_BITS: [u8; 7] = [32, 36, 40, 42, 44, 48, 52];

/// Physical-address bits for a `PARange` / `PS` encoding.
pub const fn parange_bits(field: u8) -> Option<u8> {
    if (field as usize) < PARANGE_BITS.len() { Some(PARANGE_BITS[field as usize]) } else { None }
}

/// The `VTCR_EL2` a guest runs under: 4 KiB granule, inner-shareable
/// write-back table walks, 8-bit VMIDs, no hardware A/D update.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VtcrConfig {
    ipa_bits: u8,
    ps: u8,
}

impl VtcrConfig {
    /// `ipa_bits`: the guest's IPA width. `parange`: the CPU's
    /// `ID_AA64MMFR0_EL1.PARange` (bits `[3:0]`); the output size is capped at
    /// 48 bits, the most this code can encode.
    pub const fn new(ipa_bits: u8, parange: u8) -> Result<VtcrConfig, S2Error> {
        if ipa_bits < IPA_BITS_MIN || ipa_bits > IPA_BITS_MAX {
            return Err(S2Error::BadIpaBits);
        }
        let ps = match parange_bits(parange) {
            // 52 bits needs FEAT_LPA: encode the 48-bit size instead.
            Some(52) => 5,
            Some(_) => parange,
            None => return Err(S2Error::BadParange),
        };
        // An IPA wider than the output size could name memory that does not exist.
        match parange_bits(ps) {
            Some(pa) if ipa_bits <= pa => Ok(VtcrConfig { ipa_bits, ps }),
            _ => Err(S2Error::BadIpaBits),
        }
    }

    /// The guest's IPA width.
    pub const fn ipa_bits(self) -> u8 {
        self.ipa_bits
    }

    /// Level the walk starts at.
    pub const fn start_level(self) -> u8 {
        if self.ipa_bits <= 34 {
            2
        } else if self.ipa_bits <= 43 {
            1
        } else {
            0
        }
    }

    /// Input bits one table at the start level resolves (with the 12 page bits).
    const fn start_cover_bits(self) -> u8 {
        (12 + 9 * (4 - self.start_level() as u32)) as u8
    }

    /// Concatenated root tables: 1 unless the IPA outgrows a start-level table.
    pub const fn root_tables(self) -> u64 {
        if self.ipa_bits > self.start_cover_bits() {
            1u64 << (self.ipa_bits - self.start_cover_bits())
        } else {
            1
        }
    }

    /// Alignment of the root (its own size, never below one page).
    pub const fn root_align(self) -> u64 {
        self.root_tables() * S2_PAGE
    }

    /// `VTCR_EL2.SL0` for a 4 KiB granule: 0 starts at level 2, 1 at level 1, 2 at level 0.
    const fn sl0(self) -> u64 {
        (2 - self.start_level()) as u64
    }

    /// The `VTCR_EL2` value.
    pub const fn value(self) -> u64 {
        let t0sz = (64 - self.ipa_bits) as u64;
        t0sz
            | (self.sl0() << 6)
            | (0b01 << 8)        // IRGN0: write-back, write-allocate
            | (0b01 << 10)       // ORGN0: write-back, write-allocate
            | (0b11 << 12)       // SH0: inner shareable
            | (0b00 << 14)       // TG0: 4 KiB
            | ((self.ps as u64) << 16)
            | (1u64 << 31)       // RES1
    }

    /// The `VTTBR_EL2` for a root at `root_pa` and an 8-bit `vmid`.
    pub const fn vttbr(self, root_pa: u64, vmid: u16) -> Result<u64, S2Error> {
        if vmid > 0xFF {
            return Err(S2Error::VmidTooWide);
        }
        if root_pa >> 48 != 0 {
            return Err(S2Error::PaTooWide);
        }
        if root_pa & (self.root_align() - 1) != 0 {
            return Err(S2Error::Misaligned);
        }
        Ok(root_pa | ((vmid as u64) << 48))
    }
}

/// Memory the tables live in. The kernel implements it over the direct map;
/// a host test over a plain array.
pub trait TableMem {
    /// A zeroed run of `tables` 4 KiB tables, contiguous and aligned to its
    /// own size; its physical address.
    fn alloc_tables(&mut self, tables: u64) -> Option<u64>;
    /// The descriptor at physical address `entry_pa` (8-byte aligned).
    fn read(&self, entry_pa: u64) -> u64;
    /// Store a descriptor at `entry_pa`.
    fn write(&mut self, entry_pa: u64, desc: u64);
}

/// One guest's stage-2 tables.
pub struct Stage2<'a, M: TableMem> {
    cfg: VtcrConfig,
    root: u64,
    mem: &'a mut M,
}

impl<'a, M: TableMem> Stage2<'a, M> {
    /// Allocate the root (all of its concatenated tables) from `mem`.
    pub fn new(cfg: VtcrConfig, mem: &'a mut M) -> Result<Self, S2Error> {
        let root = mem.alloc_tables(cfg.root_tables()).ok_or(S2Error::NoMemory)?;
        if root & (cfg.root_align() - 1) != 0 {
            return Err(S2Error::Misaligned);
        }
        Ok(Stage2 { cfg, root, mem })
    }

    /// Physical address of the root.
    pub fn root(&self) -> u64 {
        self.root
    }

    /// The `VTCR_EL2` / `VTTBR_EL2` pair for `vmid`.
    pub fn registers(&self, vmid: u16) -> Result<(u64, u64), S2Error> {
        Ok((self.cfg.value(), self.cfg.vttbr(self.root, vmid)?))
    }

    /// Address of the descriptor for `ipa` in the table at `table_pa`, or in
    /// the (concatenated) root when `level` is the start level.
    fn entry_pa(&self, table_pa: u64, level: u8, ipa: u64) -> u64 {
        let shift = 12 + 9 * (3 - level as u32);
        let mask = if level == self.cfg.start_level() {
            self.cfg.root_tables() * S2_ENTRIES - 1
        } else {
            S2_ENTRIES - 1
        };
        table_pa + ((ipa >> shift) & mask) * 8
    }

    fn check_ipa(&self, ipa: u64) -> Result<(), S2Error> {
        if ipa >> self.cfg.ipa_bits != 0 { Err(S2Error::IpaOutOfRange) } else { Ok(()) }
    }

    /// Map one leaf of `level_size(level)` bytes at `ipa` to `pa`, creating the
    /// tables between. Refuses to touch an existing mapping.
    pub fn map_leaf(&mut self, ipa: u64, pa: u64, level: u8, a: S2Attrs) -> Result<(), S2Error> {
        // The encoder refuses level 0 and levels past 3; a leaf above the start
        // level is not reachable by the walk.
        let leaf = leaf_desc(pa, level, a)?;
        if level < self.cfg.start_level() {
            return Err(S2Error::BadLevel);
        }
        self.check_ipa(ipa)?;
        if ipa & (level_size(level) - 1) != 0 {
            return Err(S2Error::Misaligned);
        }
        let mut table = self.root;
        let mut lvl = self.cfg.start_level();
        loop {
            let e = self.entry_pa(table, lvl, ipa);
            if lvl == level {
                if desc_valid(self.mem.read(e)) {
                    return Err(S2Error::Overlap);
                }
                self.mem.write(e, leaf);
                return Ok(());
            }
            let d = self.mem.read(e);
            table = if !desc_valid(d) {
                let t = self.mem.alloc_tables(1).ok_or(S2Error::NoMemory)?;
                self.mem.write(e, table_desc(t)?);
                t
            } else if desc_is_table(d, lvl) {
                desc_pa(d)
            } else {
                return Err(S2Error::Overlap); // a block already covers it
            };
            lvl += 1;
        }
    }

    /// Map one 4 KiB page.
    pub fn map_page(&mut self, ipa: u64, pa: u64, a: S2Attrs) -> Result<(), S2Error> {
        self.map_leaf(ipa, pa, 3, a)
    }

    /// Map the host frames of a `MemObj` to consecutive IPAs from `ipa`. Each
    /// frame is `frame_size` bytes (the kernel page size: a multiple of 4 KiB)
    /// and may be any physical address aligned to it.
    pub fn map_frames(
        &mut self,
        ipa: u64,
        frames: impl IntoIterator<Item = u64>,
        frame_size: u64,
        a: S2Attrs,
    ) -> Result<(), S2Error> {
        if frame_size == 0 || frame_size % S2_PAGE != 0 {
            return Err(S2Error::Misaligned);
        }
        let mut at = ipa;
        for frame in frames {
            if frame & (frame_size - 1) != 0 {
                return Err(S2Error::Misaligned);
            }
            let mut off = 0;
            while off < frame_size {
                self.map_page(at + off, frame + off, a)?;
                off += S2_PAGE;
            }
            at += frame_size;
        }
        Ok(())
    }

    /// Map a physically contiguous run, using 1 GiB and 2 MiB blocks wherever
    /// both addresses and the remaining length allow, pages elsewhere.
    pub fn map_run(&mut self, ipa: u64, pa: u64, len: u64, a: S2Attrs) -> Result<(), S2Error> {
        if len % S2_PAGE != 0 {
            return Err(S2Error::Misaligned);
        }
        let (mut i, mut p, mut left) = (ipa, pa, len);
        while left > 0 {
            let mut level = 3u8;
            // Block levels are only usable where the walk can place them.
            for l in [1u8, 2] {
                let sz = level_size(l);
                if l >= self.cfg.start_level() && left >= sz && (i | p) & (sz - 1) == 0 {
                    level = l;
                    break;
                }
            }
            self.map_leaf(i, p, level, a)?;
            let sz = level_size(level);
            i += sz;
            p += sz;
            left -= sz;
        }
        Ok(())
    }

    /// Unmap the 4 KiB page at `ipa`; returns the host address it mapped.
    /// The caller invalidates the TLB (`TLBI IPAS2E1IS`) before reusing it.
    pub fn unmap_page(&mut self, ipa: u64) -> Result<u64, S2Error> {
        self.check_ipa(ipa)?;
        let mut table = self.root;
        let mut lvl = self.cfg.start_level();
        loop {
            let e = self.entry_pa(table, lvl, ipa);
            let d = self.mem.read(e);
            if !desc_valid(d) {
                return Err(S2Error::NotMapped);
            }
            if lvl == 3 {
                self.mem.write(e, 0);
                return Ok(desc_pa(d));
            }
            if !desc_is_table(d, lvl) {
                return Err(S2Error::Overlap); // inside a block: unmap the block whole
            }
            table = desc_pa(d);
            lvl += 1;
        }
    }

    /// Software walk: the host address and attributes `ipa` resolves to.
    pub fn translate(&self, ipa: u64) -> Option<(u64, S2Attrs)> {
        if self.check_ipa(ipa).is_err() {
            return None;
        }
        let mut table = self.root;
        let mut lvl = self.cfg.start_level();
        loop {
            let d = self.mem.read(self.entry_pa(table, lvl, ipa));
            if !desc_valid(d) {
                return None;
            }
            if desc_is_table(d, lvl) {
                table = desc_pa(d);
                lvl += 1;
                continue;
            }
            let sz = level_size(lvl);
            return Some((desc_pa(d) | (ipa & (sz - 1)), leaf_attrs(d)?));
        }
    }
}
