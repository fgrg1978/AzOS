// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the monitor checks in a stage-1 word before it writes one into the
//! kernel half's tables: the descriptor must be well formed at its level, a
//! leaf must carry AF (the walker's hardware update would need a stage-2 write
//! the read-only pool refuses), no DBM, no contiguous hint (a run's TLB entry
//! could stand in for a frozen neighbour) and never be writable and executable
//! at EL1,
//! and the level a pool page serves is fixed by its first use. Pure, so the
//! host suite checks it.

#[path = "../../../../../arch/aarch64/src/mmu/pte_fmt.rs"]
#[allow(dead_code)] // reason: shared by source with the kernel's page-table code, which uses the rest
pub mod pte_fmt;

use core::sync::atomic::{AtomicU64, Ordering};
use pte_fmt::*;

/// A pool page's tag: set once the page has a level, `TAG_IMAGE` when it maps,
/// or leads to a table that maps, the locked image.
pub const TAG_SET: u8 = 0x80;
pub const TAG_IMAGE: u8 = 0x40;
const TAG_LEVEL: u8 = 0x3;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Word {
    Invalid,
    Table(u64),
    Leaf { pa: u64, size: u64 },
}

pub const fn block_size(level: usize, page_shift: u32) -> u64 {
    1 << (page_shift + (page_shift - 3) * level as u32)
}

pub fn classify(word: u64, level: usize, page_shift: u32) -> Result<Word, &'static str> {
    if !is_valid(word) {
        return Ok(Word::Invalid);
    }
    let pa = phys_addr(word) as u64;
    if is_table(word, level) {
        if word != make_table(pa as usize) { return Err("table descriptor with attributes"); }
        if pa % (1 << page_shift) != 0 { return Err("table not page-aligned"); }
        return Ok(Word::Table(pa));
    }
    if is_leaf(word, level) {
        let size = block_size(level, page_shift);
        if pa % size != 0 { return Err("leaf not aligned to its size"); }
        return Ok(Word::Leaf { pa, size });
    }
    Err("reserved descriptor")
}

fn overlaps(lo: u64, hi: u64, r: [u64; 2]) -> bool {
    lo < r[1] && r[0] < hi
}

/// Why a well-formed word may not be written; `None`: it may.
pub fn word_error(w: Word, word: u64) -> Option<&'static str> {
    if !matches!(w, Word::Leaf { .. }) { return None; }
    if word & AF == 0 { return Some("leaf without AF"); }
    if word & DBM != 0 { return Some("leaf with DBM"); }
    if word & CONT != 0 { return Some("leaf with the contiguous hint"); }
    if el1_writable(word) && el1_executable(word) { return Some("leaf writable and executable"); }
    None
}

/// Why a word already in the tables at the lock is refused: it breaks the
/// rules of any word, or it is a block over the image (a later split of it would
/// have to rewrite a frozen slot, so the lock fails where it is reported).
pub fn lock_word_error(w: Word, word: u64, level: usize, image: &[[u64; 2]]) -> Option<&'static str> {
    if level > 0 && maps_image(w, image) { return Some("a block leaf over the image"); }
    word_error(w, word)
}

/// Why a pool page the lock's walk did not reach is refused: it has words that
/// nothing checked.
pub fn unreached_error(tag: u8, mut words: impl Iterator<Item = u64>) -> Option<&'static str> {
    if tag & TAG_SET == 0 && words.any(|w| w != 0) { Some("a pool page nothing links has words in it") } else { None }
}

/// Does a leaf map the locked image? Such a word, and the table that holds
/// the way to it, never change.
pub fn maps_image(w: Word, image: &[[u64; 2]]) -> bool {
    matches!(w, Word::Leaf { pa, size } if image.iter().any(|i| overlaps(pa, pa + size, *i)))
}

pub const fn tag_of(level: usize) -> u8 {
    TAG_SET | level as u8
}

pub const fn tag_level(tag: u8) -> Option<usize> {
    if tag & TAG_SET != 0 { Some((tag & TAG_LEVEL) as usize) } else { None }
}

/// The tag after a page is used at `level`: a page with none takes it, one
/// with a level keeps it only if it is the same.
pub fn claim(tag: u8, level: usize) -> Result<u8, &'static str> {
    match tag_level(tag) {
        None => Ok(tag_of(level)),
        Some(l) if l == level => Ok(tag),
        Some(_) => Err("page serves another level"),
    }
}

/// The pages a checked write fixes the level of: the one it writes into
/// (`entry`) and the table it links, with the level that table serves.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    pub entry: usize,
    pub target: Option<(u64, usize)>,
}

/// Why replacing `expected` by `new` in a table of `level` is refused; the
/// claims it makes otherwise. `in_pool` says whether a table address is a pool
/// page, `tag` gives a pool page's tag.
pub fn write_error(
    expected: u64,
    new: u64,
    level: usize,
    entry_tag: u8,
    page_shift: u32,
    image: &[[u64; 2]],
    in_pool: impl Fn(u64) -> bool,
    tag: impl Fn(u64) -> u8,
) -> Result<Claims, &'static str> {
    claim(entry_tag, level)?;
    let now = classify(expected, level, page_shift)?;
    if expected != new {
        if maps_image(now, image) { return Err("slot maps the image"); }
        if let Word::Table(t) = now {
            if in_pool(t) && tag(t) & TAG_IMAGE != 0 { return Err("slot leads to the image"); }
        }
    }
    let w = classify(new, level, page_shift)?;
    if let Some(e) = word_error(w, new) { return Err(e); }
    let target = match w {
        Word::Table(t) if !in_pool(t) => return Err("table outside the pool"),
        Word::Table(t) => {
            claim(tag(t), level - 1)?;
            Some((t, level - 1))
        }
        _ => None,
    };
    Ok(Claims { entry: level, target })
}

/// The leaf `va` resolves to from `root`, with its physical address: `read`
/// gives the word at a physical address. `None` when the walk meets an
/// invalid word, a reserved one, or a table where the levels run out.
pub fn resolve(read: impl Fn(u64) -> u64, root: u64, va: u64, page_shift: u32) -> Option<(u64, u64)> {
    let bits = page_shift - 3;
    let mut table = root;
    for level in (0..LEVELS).rev() {
        let idx = (va >> (page_shift + bits * level as u32)) & ((1 << bits) - 1);
        let word = read(table + idx * 8);
        match classify(word, level, page_shift).ok()? {
            Word::Invalid => return None,
            Word::Table(t) => table = t,
            Word::Leaf { pa, size } => return Some((pa + (va & (size - 1)), word)),
        }
    }
    None
}

/// Why the image does not live where the kernel says: every page of
/// `[va, va + len)` must resolve to the matching page of `pa`, read-only, and
/// executable only for text.
pub fn image_error(read: impl Fn(u64) -> u64, root: u64, va: u64, pa: u64, len: u64, text: bool, page_shift: u32) -> Option<&'static str> {
    let page = 1u64 << page_shift;
    let mut off = 0;
    while off < len {
        let Some((got, word)) = resolve(&read, root, va + off, page_shift) else { return Some("image page not mapped") };
        if got != pa + off { return Some("image page maps another frame"); }
        if el1_writable(word) { return Some("image page writable"); }
        if el1_executable(word) != text { return Some(if text { "text page not executable" } else { "data page executable" }); }
        off += page;
    }
    None
}

/// `TTBR1_EL1.BADDR` (bits 47:1; bit 0 is CnP) and the ASID field.
pub const TTBR1_BADDR: u64 = 0x0000_FFFF_FFFF_FFFE;
const TTBR1_ASID: u64 = 0xFFFF << 48;
/// The `TCR_EL1` fields that decide how a `TTBR1_EL1` walk reads the tables:
/// T1SZ, IRGN1, ORGN1, SH1, TG1 and DS. EPD1 (a boot step turns the half off), A1
/// and the rest (HA, TBI, IPS) are not the monitor's to compare: with the root
/// the monitor's, a half that is off or read by another ASID reaches nothing.
pub const TCR_WALK: u64 = 0xFF3F_0000 | TCR_DS;
/// `TCR_EL1.DS` (FEAT_LPA2): it changes how descriptor bits 9:8 are read.
pub const TCR_DS: u64 = 1 << 59;
/// `TCR_EL1.EPD1`: the upper half is off, whatever else the register says.
pub const TCR_EPD1: u64 = 1 << 23;

/// Why a PE's `TTBR1_EL1` is not the locked root.
pub fn ttbr1_error(ttbr1: u64, root: u64) -> Option<&'static str> {
    if ttbr1 & TTBR1_ASID != 0 { return Some("TTBR1 carries an ASID"); }
    if ttbr1 & TTBR1_BADDR != root { return Some("TTBR1 is not the locked root"); }
    None
}

/// Why a PE's `TCR_EL1` reads the kernel half differently from the one the
/// pool was locked under.
pub fn tcr_error(tcr: u64, locked: u64) -> Option<&'static str> {
    if (tcr ^ locked) & TCR_WALK != 0 { Some("TCR walks the kernel half differently") } else { None }
}

/// `SCTLR_EL1.M`, and the bits that change how the walk reads the tables or what
/// a leaf's permissions mean: E0E and EE (byte order) and WXN.
const SCTLR_M: u64 = 1;
pub const SCTLR_FIXED: u64 = 1 << 25 | 1 << 24 | 1 << 19;

/// Why an `SCTLR_EL1` value is not one the kernel may run with: the MMU off, or
/// a byte order or WXN other than the locked one's.
pub fn sctlr_error(v: u64, locked: u64) -> Option<&'static str> {
    if v & SCTLR_M == 0 { return Some("SCTLR turns the MMU off"); }
    if (v ^ locked) & SCTLR_FIXED != 0 { return Some("SCTLR changes the byte order or WXN"); }
    None
}

/// The registers the pool was locked under, from the calling core.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Locked {
    pub ttbr1: u64,
    pub tcr: u64,
    pub sctlr: u64,
}

/// Why a core that is about to run the kernel may not: the pool is locked and
/// its `TTBR1_EL1`, `TCR_EL1` or `SCTLR_EL1` are not the locked ones.
pub fn pe_regs_error(live: Locked, locked: Locked) -> Option<&'static str> {
    ttbr1_error(live.ttbr1, locked.ttbr1 & TTBR1_BADDR)
        .or_else(|| tcr_error(live.tcr, locked.tcr))
        .or_else(|| sctlr_error(live.sctlr, locked.sctlr))
}

/// Why `pt_lock_pool` is refused for the calling core: it has not pinned, or its
/// `TTBR1_EL1` is not the root the caller names.
pub fn lock_regs_error(pinned: bool, ttbr1: u64, root: u64) -> Option<&'static str> {
    if !pinned { return Some("the calling core has not pinned"); }
    ttbr1_error(ttbr1, root)
}

/// What the monitor sets on a core before it enters EL1 at the secondary or
/// resume entry: once the pool is locked, the locked `TTBR1_EL1` and `TCR_EL1`,
/// whatever the kernel's data says, with the writes to them trapped.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EntryPlan {
    pub ttbr1: u64,
    pub tcr: u64,
}

pub fn entry_plan(locked: Option<Locked>) -> Option<EntryPlan> {
    locked.map(|l| EntryPlan { ttbr1: l.ttbr1, tcr: l.tcr })
}

/// The registers whose EL1 writes are trapped once the pool is locked.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Vm {
    Sctlr,
    Tcr,
    Ttbr1,
}

/// Why a `TCR_EL1` value may not be written: it reads the kernel half differently
/// from the locked one while the half is on. A value with EPD1 set (the boot's
/// identity-map form, T1 fields zero) turns the half off and reaches nothing.
pub fn tcr_write_error(v: u64, locked: u64) -> Option<&'static str> {
    if v & TCR_EPD1 != 0 { None } else { tcr_error(v, locked) }
}

/// May the monitor carry out a trapped EL1 write of `v` to `reg`? Before the pool
/// is locked, no (the pin refuses them). After it: `TTBR1_EL1` only to the locked
/// root, `TCR_EL1` only with the locked walk fields or the half off, `SCTLR_EL1`
/// only with the MMU on and the locked byte order and WXN, pinned or not; everything
/// else is dropped.
pub fn write_allowed(reg: Vm, v: u64, locked: Option<Locked>) -> bool {
    let Some(l) = locked else { return false };
    match reg {
        Vm::Ttbr1 => ttbr1_error(v, l.ttbr1 & TTBR1_BADDR).is_none(),
        Vm::Tcr => tcr_write_error(v, l.tcr).is_none(),
        Vm::Sctlr => sctlr_error(v, l.sctlr).is_none(),
    }
}

/// The affinity that names a core: Aff3:Aff2:Aff1:Aff0 of `MPIDR_EL1`. Aff0 alone
/// does not (a DynamIQ core's number is in Aff1 and every Aff0 is 0).
pub const fn affinity(mpidr: u64) -> u64 {
    mpidr & AFF_MASK
}

/// Aff3:Aff2:Aff1:Aff0 of an `MPIDR_EL1`.
pub const AFF_MASK: u64 = 0x0000_00FF_00FF_FFFF;

/// The EL2 stack and resume-context slots, one per core by full affinity: a
/// core that goes off or down and comes back finds the slot it had, so slots
/// are not used up by power cycles. The entry stub (`entry.rs`) reads `keys`
/// by symbol (first field) and checks the slot holds the core's own key before
/// it takes the slot's stack; `psci.rs` claims the slot of a core it is about
/// to start or that is about to power down, and stores the context the kernel
/// wants back in x0 there.
#[repr(C)]
pub struct PeSlots<const N: usize> {
    pub keys: [AtomicU64; N],
    ctx: [AtomicU64; N],
}

impl<const N: usize> PeSlots<N> {
    pub const fn new() -> Self {
        PeSlots { keys: [const { AtomicU64::new(0) }; N], ctx: [const { AtomicU64::new(0) }; N] }
    }

    /// Remember `ctx` for the core `aff` (the kernel's x0 when it resumes) and
    /// give back its slot, the value the monitor passes through firmware.
    pub fn record(&self, aff: u64, ctx: u64) -> Option<usize> {
        let slot = self.claim(aff)?;
        self.ctx[slot].store(ctx, Ordering::Release);
        Some(slot)
    }

    /// The context stored for `slot`; 0 for a slot out of range.
    pub fn ctx_of(&self, slot: usize) -> u64 {
        self.ctx.get(slot).map_or(0, |c| c.load(Ordering::Acquire))
    }

    /// The word a slot holds for an affinity (never 0, which is free); the
    /// entry stub builds the same from `MPIDR_EL1`.
    pub const fn key(aff: u64) -> u64 {
        // Canary `hyp-pe-aff0-canary` (host suite only): the core's number is taken from Aff0 alone.
        (aff & if cfg!(feature = "hyp-pe-aff0-canary") { 0xff } else { AFF_MASK }) | 1 << 63
    }

    /// The slot of `aff`, taking the first free one if it has none. Slots fill
    /// in order and are never given back, so a core is found before any free
    /// slot is reached. `None` when every slot belongs to another core: cores,
    /// not power cycles, are what `N` bounds.
    pub fn claim(&self, aff: u64) -> Option<usize> {
        let key = Self::key(aff);
        // Canary `hyp-pe-seq-canary` (host suite only): every call takes a fresh slot, as the old counter did.
        if cfg!(feature = "hyp-pe-seq-canary") {
            return self.keys.iter().position(|s| s.compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire).is_ok());
        }
        for (i, s) in self.keys.iter().enumerate() {
            match s.compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(i),
                Err(cur) if cur == key => return Some(i),
                Err(_) => {}
            }
        }
        None
    }
}

/// The cores that have pinned, by affinity.
pub struct PinTable<const N: usize>([AtomicU64; N]);

impl<const N: usize> PinTable<N> {
    pub const fn new() -> Self {
        PinTable([const { AtomicU64::new(0) }; N])
    }

    /// The slot value of an affinity (never 0, which is empty).
    const fn key(aff: u64) -> u64 {
        aff | 1 << 63
    }

    pub fn contains(&self, aff: u64) -> bool {
        self.0.iter().any(|s| s.load(Ordering::Acquire) == Self::key(aff))
    }

    /// Record a pinned core; false when the table is full.
    pub fn insert(&self, aff: u64) -> bool {
        if self.contains(aff) { return true; }
        self.0.iter().any(|s| s.compare_exchange(0, Self::key(aff), Ordering::AcqRel, Ordering::Acquire).is_ok())
    }

    /// The core is off, or about to power down: it pins again when it is back.
    pub fn remove(&self, aff: u64) {
        for s in self.0.iter() {
            let _ = s.compare_exchange(Self::key(aff), 0, Ordering::AcqRel, Ordering::Acquire);
        }
    }

    pub fn count(&self) -> u64 {
        self.0.iter().filter(|s| s.load(Ordering::Acquire) != 0).count() as u64
    }
}

/// What the CPU has that changes how a stage-1 descriptor or the walk is read and
/// that the monitor does not check word by word.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Extensions {
    /// None of `TCR2_EL1`, `PIR_EL1`: nothing to do.
    None,
    /// FEAT_TCRX or FEAT_S1PIE, with FEAT_HCX to trap them: `HCRX_EL2` is
    /// programmed to trap EL1's accesses and `TCR2_EL1` is zeroed.
    Trap,
    /// FEAT_TCRX or FEAT_S1PIE without FEAT_HCX: no way to hold them, the lock is refused.
    Unenforceable,
}

/// `ID_AA64MMFR1_EL1.HCX` (bits 43:40) and `ID_AA64MMFR3_EL1.TCRX` (3:0), `S1PIE` (11:8), `S1POE` (19:16).
pub fn extensions(mmfr1: u64, mmfr3: u64) -> Extensions {
    if mmfr3 & (0xf | 0xf << 8 | 0xf << 16) == 0 { return Extensions::None; }
    if (mmfr1 >> 40) & 0xf != 0 { Extensions::Trap } else { Extensions::Unenforceable }
}
