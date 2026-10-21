// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The forwarding windows of PCI-to-PCI bridges.
//!
//! A bridge passes a memory access downstream only inside its two windows
//! (non-prefetchable below 4 GiB, prefetchable up to 64 bits), so a BAR
//! behind one is unreachable until the bridge's window covers it. Nothing
//! runs a PCI init step ahead of this kernel on QEMU `virt`, and a board's
//! firmware may leave bridges dark, so [`place_behind_bridges`] does it: it
//! sizes each bridge's windows around what sits behind it, carves them out
//! of the host bridge's windows ([`BarWindow`]), fixes an address for every
//! BAR behind a bridge inside its bridge's window (the driver that later
//! asks [`BarWindow::alloc_bar`] gets that address), and programs the
//! bridges.
//!
//! Endpoints on bus 0 are not touched: their BARs are placed on demand, from
//! what the bridge windows leave.
//!
//! A bridge the firmware already opened a window on is left as found, and so
//! is everything behind it: its endpoints keep the addresses the firmware
//! gave them.

use core::fmt;

use crate::window::{BarWindow, Pool};
use crate::{
    set_command_bits, Bar, BarKind, Bdf, ConfigSpace, FunctionInfo, CMD_BUS_MASTER, CMD_MEM_SPACE,
    HEADER_TYPE_BRIDGE, HEADER_TYPE_MASK, OFF_HEADER_TYPE, OFF_SECONDARY_BUS, OFF_SUBORDINATE_BUS,
};

/// Bridges one plan covers. More and the rest are left as found.
pub const MAX_BRIDGES: usize = 16;

/// A bridge window's base and size are multiples of 1 MiB.
const GRANULE: u64 = 1 << 20;
/// Items (BARs and child-bridge windows) placed on one bus.
const MAX_ITEMS: usize = 64;

/// Non-prefetchable memory base (`+0`) and limit (`+2`).
const OFF_MEM_BASE: u16 = 0x20;
/// Prefetchable memory base (`+0`) and limit (`+2`); bit 0 of each is 1 when
/// the bridge decodes 64 bits.
const OFF_PREF_BASE: u16 = 0x24;
const OFF_PREF_BASE_HI: u16 = 0x28;
const OFF_PREF_LIMIT_HI: u16 = 0x2c;

/// Window classes: non-prefetchable (and everything that must sit below
/// 4 GiB) and 64-bit prefetchable.
const MEM: usize = 0;
const PREF: usize = 1;

/// What was programmed into one bridge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BridgeWindows {
    pub bdf: Bdf,
    pub secondary: u8,
    pub subordinate: u8,
    /// Non-prefetchable window `(base, size)`.
    pub mem: Option<(u64, u64)>,
    /// Prefetchable window `(base, size)`.
    pub pref: Option<(u64, u64)>,
}

/// What [`place_behind_bridges`] did.
#[derive(Clone, Debug)]
pub struct BridgePlan {
    bridges: [Option<BridgeWindows>; MAX_BRIDGES],
    len: usize,
    /// Bridges left as found: windows the firmware opened (and the bridges
    /// below them), bridges without buses, bridges past [`MAX_BRIDGES`].
    pub left_alone: usize,
    /// BARs and windows that did not fit; their devices stay unreachable.
    pub unplaced: usize,
}

impl BridgePlan {
    pub fn iter(&self) -> impl Iterator<Item = &BridgeWindows> {
        self.bridges[..self.len].iter().flatten()
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0 && self.left_alone == 0 && self.unplaced == 0
    }
}

impl fmt::Display for BridgePlan {
    /// `bridge 00:02.0 buses 1-1 mem 0x40000000+0x100000 pref 0x400000000+0x100000; ...`
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for b in self.iter() {
            if !first {
                f.write_str("; ")?;
            }
            first = false;
            write!(f, "bridge {} buses {}-{}", b.bdf, b.secondary, b.subordinate)?;
            if let Some((base, size)) = b.mem {
                write!(f, " mem {:#x}+{:#x}", base, size)?;
            }
            if let Some((base, size)) = b.pref {
                write!(f, " pref {:#x}+{:#x}", base, size)?;
            }
        }
        if self.left_alone != 0 {
            write!(f, "{}{} left as found", if first { "" } else { "; " }, self.left_alone)?;
            first = false;
        }
        if self.unplaced != 0 {
            write!(f, "{}{} BAR(s) unplaced", if first { "" } else { "; " }, self.unplaced)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Br {
    bdf: Bdf,
    sec: u8,
    sub: u8,
    /// Firmware opened a window here (or on a bridge above): leave alone.
    skip: bool,
    /// Pow2 size of each window class, 0 when nothing sits behind.
    ext: [u64; 2],
    /// Where the parent carved each class (`None`: not placed).
    base: [Option<u64>; 2],
    /// Does a prefetchable window above 4 GiB reach the BARs on this
    /// bridge's bus: a 64-bit pool exists, this bridge decodes 64 bits
    /// (low nibble of its prefetchable base is 1) and so does every bridge
    /// above it? When not, those BARs take the memory window.
    pref64: bool,
}

#[derive(Clone, Copy)]
enum Who {
    Bar(Bdf, u8),
    Bridge(usize),
}

#[derive(Clone, Copy)]
struct Item {
    size: u64,
    who: Who,
}

/// The pow2 window that holds `sum` bytes. A sum no window can hold (the
/// device-controlled sizes overflowed `u64`, or it rounds past 2^63) comes
/// out as `u64::MAX`, which is no power of two: it is never carved and is
/// counted as unplaced, never silently dropped.
const fn pow2_window(sum: u64) -> u64 {
    if sum == 0 {
        0
    } else if sum <= GRANULE {
        GRANULE
    } else {
        match sum.checked_next_power_of_two() {
            Some(w) => w,
            None => u64::MAX,
        }
    }
}

/// Which window class `bar` needs; `None` for an I/O BAR (not assigned).
fn class_of(bar: &Bar, have_pref64: bool) -> Option<usize> {
    match bar.kind {
        BarKind::Io => None,
        BarKind::Mem64 if bar.prefetchable && have_pref64 => Some(PREF),
        _ => Some(MEM),
    }
}

/// Is a forwarding window programmed: base and limit not both zero (the
/// reset state) and base not above limit?
fn window_open(base: u64, limit: u64) -> bool {
    !(base == 0 && limit == 0) && base <= limit
}

fn firmware_opened_a_window<C: ConfigSpace>(cfg: &C, bdf: Bdf) -> bool {
    let m = cfg.read32(bdf, OFF_MEM_BASE);
    let mem_base = ((m & 0xfff0) as u64) << 16;
    let mem_limit = (((m >> 16) & 0xfff0) as u64) << 16 | 0xf_ffff;
    let p = cfg.read32(bdf, OFF_PREF_BASE);
    let hi_base = cfg.read32(bdf, OFF_PREF_BASE_HI) as u64;
    let hi_limit = cfg.read32(bdf, OFF_PREF_LIMIT_HI) as u64;
    let pref_base = hi_base << 32 | ((p & 0xfff0) as u64) << 16;
    let pref_limit = hi_limit << 32 | (((p >> 16) & 0xfff0) as u64) << 16 | 0xf_ffff;
    // The "all zero" reset state is judged on the registers, not on the
    // limits above (a zero limit register still decodes up to the granule).
    (m & 0xfff0_fff0 != 0 && window_open(mem_base, mem_limit))
        || ((p & 0xfff0_fff0 != 0 || hi_base != 0 || hi_limit != 0) && window_open(pref_base, pref_limit))
}

fn insertion_sort_desc(items: &mut [Item]) {
    for i in 1..items.len() {
        let mut j = i;
        while j > 0 && items[j - 1].size < items[j].size {
            items.swap(j - 1, j);
            j -= 1;
        }
    }
}

/// Place everything that sits on `bus` (its BARs when `with_bars`, and the
/// windows of the bridges whose parent bus it is) of window class `class`
/// into `pool`, largest first, so that every item is aligned to its size and
/// the total is exactly the sum of the sizes.
fn place_bus(
    funcs: &[Option<FunctionInfo>],
    bs: &mut [Option<Br>],
    bus: u8,
    with_bars: bool,
    class: usize,
    bus_pref64: bool,
    pool: &mut Pool,
    window: &mut BarWindow,
    unplaced: &mut usize,
) {
    let mut items = [Item { size: 0, who: Who::Bridge(0) }; MAX_ITEMS];
    let mut n = 0usize;
    let mut push = |it: Item, unplaced: &mut usize| {
        if n < MAX_ITEMS {
            items[n] = it;
            n += 1;
        } else {
            *unplaced += 1;
        }
    };
    if with_bars {
        for f in funcs.iter().flatten().filter(|f| f.bdf.bus == bus) {
            for bar in f.bars[..f.bar_count].iter().flatten() {
                if class_of(bar, bus_pref64) == Some(class) {
                    push(Item { size: bar.size, who: Who::Bar(f.bdf, bar.index) }, unplaced);
                }
            }
        }
    }
    for (j, b) in bs.iter().enumerate() {
        if let Some(b) = b {
            if !b.skip && b.bdf.bus == bus && b.ext[class] != 0 {
                push(Item { size: b.ext[class], who: Who::Bridge(j) }, unplaced);
            }
        }
    }
    insertion_sort_desc(&mut items[..n]);
    for it in &items[..n] {
        let Some(addr) = pool.alloc(it.size) else {
            *unplaced += 1;
            continue;
        };
        match it.who {
            Who::Bar(bdf, index) => {
                if !window.reserve(bdf, index, addr) {
                    *unplaced += 1;
                }
            }
            Who::Bridge(j) => {
                if let Some(b) = bs[j].as_mut() {
                    b.base[class] = Some(addr);
                }
            }
        }
    }
}

/// Program the non-prefetchable window `[base, base + size)` of `bdf`.
fn program_mem<C: ConfigSpace>(cfg: &mut C, bdf: Bdf, base: u64, size: u64) -> bool {
    let limit = base + size - 1;
    if limit > u32::MAX as u64 {
        return false;
    }
    let v = (((limit >> 16) & 0xfff0) << 16) | ((base >> 16) & 0xfff0);
    cfg.write32(bdf, OFF_MEM_BASE, v as u32);
    true
}

/// Program the prefetchable window `[base, base + size)` of `bdf`. The low
/// nibble of each half says whether the bridge decodes 64 bits and is kept;
/// a window above 4 GiB needs that.
fn program_pref<C: ConfigSpace>(cfg: &mut C, bdf: Bdf, base: u64, size: u64) -> bool {
    let limit = base + size - 1;
    let old = cfg.read32(bdf, OFF_PREF_BASE);
    if limit > u32::MAX as u64 && old & 0xf != 1 {
        return false;
    }
    let v = (old & 0x000f_000f) | (((limit >> 16) & 0xfff0) << 16) as u32 | ((base >> 16) & 0xfff0) as u32;
    cfg.write32(bdf, OFF_PREF_BASE, v);
    cfg.write32(bdf, OFF_PREF_BASE_HI, (base >> 32) as u32);
    cfg.write32(bdf, OFF_PREF_LIMIT_HI, (limit >> 32) as u32);
    true
}

/// Size, carve and program the windows of every bridge in `funcs` (as
/// [`crate::enumerate_tree`] returned them), and fix the address of every BAR
/// behind one. See the module doc. Memory decode and bus mastering are
/// turned on for each bridge that gets a window.
pub fn place_behind_bridges<C: ConfigSpace>(
    cfg: &mut C,
    funcs: &[Option<FunctionInfo>],
    window: &mut BarWindow,
) -> BridgePlan {
    let mut plan = BridgePlan { bridges: [None; MAX_BRIDGES], len: 0, left_alone: 0, unplaced: 0 };
    let have_pref64 = window.has_pref64();

    // The bridges that lead somewhere, by secondary bus.
    let mut bs: [Option<Br>; MAX_BRIDGES] = [None; MAX_BRIDGES];
    let mut n = 0usize;
    for f in funcs.iter().flatten() {
        if cfg.read8(f.bdf, OFF_HEADER_TYPE) & HEADER_TYPE_MASK != HEADER_TYPE_BRIDGE {
            continue;
        }
        let sec = cfg.read8(f.bdf, OFF_SECONDARY_BUS);
        let sub = cfg.read8(f.bdf, OFF_SUBORDINATE_BUS);
        if sec == 0 || sec <= f.bdf.bus || bs[..n].iter().flatten().any(|b| b.sec == sec) {
            plan.left_alone += 1;
            continue;
        }
        if n == MAX_BRIDGES {
            plan.left_alone += 1;
            continue;
        }
        let skip = firmware_opened_a_window(cfg, f.bdf);
        let decodes64 = cfg.read32(f.bdf, OFF_PREF_BASE) & 0xf == 1;
        bs[n] = Some(Br { bdf: f.bdf, sec, sub, skip, ext: [0; 2], base: [None; 2], pref64: decodes64 });
        n += 1;
    }
    // Parents before children: a child's bus number is above its parent's.
    for i in 1..n {
        let mut j = i;
        while j > 0 && bs[j - 1].map(|b| b.sec) > bs[j].map(|b| b.sec) {
            bs.swap(j - 1, j);
            j -= 1;
        }
    }
    // A bridge on a bus nobody numbered, or below a bridge left as found,
    // is left as found.
    for i in 0..n {
        let b = bs[i].unwrap();
        if b.bdf.bus != 0 {
            let parent_ok = bs[..i].iter().flatten().any(|p| p.sec == b.bdf.bus && !p.skip);
            if !parent_ok && !bs[i].unwrap().skip {
                bs[i].as_mut().unwrap().skip = true;
            }
        }
    }
    plan.left_alone += bs[..n].iter().flatten().filter(|b| b.skip).count();
    // 64-bit prefetchable reach: the pool exists and every bridge on the
    // way decodes 64 bits (parents come first).
    for i in 0..n {
        let b = bs[i].unwrap();
        let above = b.bdf.bus == 0 || bs[..i].iter().flatten().any(|p| p.sec == b.bdf.bus && p.pref64);
        bs[i].as_mut().unwrap().pref64 = have_pref64 && b.pref64 && above;
    }

    // Sizes, children first (the highest bus number first).
    for class in [MEM, PREF] {
        for i in (0..n).rev() {
            let b = bs[i].unwrap();
            if b.skip {
                continue;
            }
            let mut sum = 0u64;
            for f in funcs.iter().flatten().filter(|f| f.bdf.bus == b.sec) {
                for bar in f.bars[..f.bar_count].iter().flatten() {
                    if class_of(bar, b.pref64) == Some(class) {
                        sum = sum.saturating_add(bar.size);
                    }
                }
            }
            for c in bs[..n].iter().flatten().filter(|c| !c.skip && c.bdf.bus == b.sec) {
                sum = sum.saturating_add(c.ext[class]);
            }
            bs[i].as_mut().unwrap().ext[class] = pow2_window(sum);
        }
    }

    // Carving, parents first: the root pools hand out the windows of the
    // bridges on bus 0, each bridge's window hands out its bus's.
    let mut pool = window.mem32;
    place_bus(funcs, &mut bs[..n], 0, false, MEM, false, &mut pool, window, &mut plan.unplaced);
    window.mem32 = pool;
    let mut pool = window.pref64;
    place_bus(funcs, &mut bs[..n], 0, false, PREF, false, &mut pool, window, &mut plan.unplaced);
    window.pref64 = pool;
    for i in 0..n {
        let b = bs[i].unwrap();
        if b.skip {
            continue;
        }
        for class in [MEM, PREF] {
            if let Some(base) = b.base[class] {
                let mut pool = Pool::new(base, b.ext[class]);
                place_bus(funcs, &mut bs[..n], b.sec, true, class, b.pref64, &mut pool, window, &mut plan.unplaced);
            }
        }
    }

    // Programming.
    for b in bs[..n].iter().flatten().filter(|b| !b.skip) {
        let mut done = BridgeWindows { bdf: b.bdf, secondary: b.sec, subordinate: b.sub, mem: None, pref: None };
        if let Some(base) = b.base[MEM] {
            if program_mem(cfg, b.bdf, base, b.ext[MEM]) {
                done.mem = Some((base, b.ext[MEM]));
            } else {
                plan.unplaced += 1;
                window.release(b.sec, b.sub, base, b.ext[MEM]);
            }
        }
        if let Some(base) = b.base[PREF] {
            if program_pref(cfg, b.bdf, base, b.ext[PREF]) {
                done.pref = Some((base, b.ext[PREF]));
            } else {
                plan.unplaced += 1;
                window.release(b.sec, b.sub, base, b.ext[PREF]);
            }
        }
        if done.mem.is_some() || done.pref.is_some() {
            set_command_bits(cfg, b.bdf, CMD_MEM_SPACE | CMD_BUS_MASTER);
            if plan.len < MAX_BRIDGES {
                plan.bridges[plan.len] = Some(done);
                plan.len += 1;
            }
        }
    }
    plan
}
