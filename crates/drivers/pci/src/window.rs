// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-bridge memory windows and the allocator BARs are placed from.
//!
//! Two windows exist: the 32-bit one (below 4 GiB; the only place a
//! non-prefetchable BAR can live behind a bridge) and the 64-bit one above
//! it, where prefetchable 64-bit BARs go. A firmware that states them (DT
//! `ranges`) is believed; one that does not leaves the built-in defaults.
//! The CPU must be able to reach what is handed out: a window the kernel's
//! address space cannot map is clipped to that reach, never used blindly.
//!
//! Two address spaces meet here. Everything this module hands out and every
//! BAR and bridge window is programmed with a PCI BUS address; what the
//! kernel maps and a driver dereferences is the CPU address the host bridge
//! translates it to (DT `ranges` with `bus != cpu`, as on many SoC host
//! bridges). The pools hold bus addresses; [`BarWindow::bar_cpu_addr`] is the
//! one way from a bus address to the CPU one.

use core::fmt;

use crate::{Bar, BarKind, Bdf};

/// A bump allocator over one bus-address range. BAR sizes are powers of two
/// and a BAR must be naturally aligned to its size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pool {
    next: u64,
    end: u64,
}

impl Pool {
    pub const EMPTY: Pool = Pool { next: 0, end: 0 };

    /// Range `[base, base + size)`.
    pub const fn new(base: u64, size: u64) -> Self {
        Pool { next: base, end: base.saturating_add(size) }
    }

    /// Reserve `size` bytes aligned to `size`. `None` if `size` is not a
    /// power of two or the range is exhausted.
    pub fn alloc(&mut self, size: u64) -> Option<u64> {
        if size == 0 || !size.is_power_of_two() {
            return None;
        }
        let addr = self.next.checked_add(size - 1)? & !(size - 1);
        let top = addr.checked_add(size)?;
        if top > self.end {
            return None;
        }
        self.next = top;
        Some(addr)
    }

    /// First address not handed out yet and the end of the range.
    pub const fn span(&self) -> (u64, u64) {
        (self.next, self.end)
    }
}

/// One host-bridge window in both address spaces: bus addresses
/// `[bus_base, bus_base + size)` appear to the CPU at `bus + delta`
/// (wrapping, so the CPU address may be below or above the bus one).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Xlat {
    bus_base: u64,
    size: u64,
    delta: u64,
}

const NO_XLAT: Xlat = Xlat { bus_base: 0, size: 0, delta: 0 };

impl Xlat {
    /// Does `[bus, bus + len)` lie inside this window?
    fn holds(&self, bus: u64, len: u64) -> bool {
        match (bus.checked_add(len), self.bus_base.checked_add(self.size)) {
            (Some(end), Some(top)) => self.size != 0 && bus >= self.bus_base && end <= top,
            _ => false,
        }
    }
}

/// BARs behind bridges whose address was fixed ahead of their driver asking
/// (the bridge windows are sized around them). More than this and the rest
/// are placed on demand, outside any bridge window.
pub const MAX_RESERVED: usize = 64;

#[derive(Clone, Copy, Debug)]
struct Reserved {
    bdf: Bdf,
    index: u8,
    addr: u64,
}

const MEM32: usize = 0;
const PREF64: usize = 1;

const NO_RESERVATION: Reserved = Reserved { bdf: Bdf::new(0, 0, 0), index: 0xff, addr: 0 };

/// Where BARs are placed from: the 32-bit memory window, the 64-bit
/// prefetchable one (possibly empty), and the addresses already fixed for
/// functions behind bridges ([`crate::place_behind_bridges`]). All of them
/// are bus addresses.
#[derive(Clone, Debug)]
pub struct BarWindow {
    pub(crate) mem32: Pool,
    pub(crate) pref64: Pool,
    /// Bus -> CPU translation of `mem32` and `pref64`.
    xlat: [Xlat; 2],
    reserved: [Reserved; MAX_RESERVED],
    n_reserved: usize,
}

impl BarWindow {
    /// A 32-bit window `[base, base + size)` (bus addresses, seen by the CPU
    /// at the same addresses) and no 64-bit one.
    pub const fn new(base: u64, size: u64) -> Self {
        BarWindow {
            mem32: Pool::new(base, size),
            pref64: Pool::EMPTY,
            xlat: [Xlat { bus_base: base, size, delta: 0 }, NO_XLAT],
            reserved: [NO_RESERVATION; MAX_RESERVED],
            n_reserved: 0,
        }
    }

    /// The same, with the 64-bit prefetchable window `[base, base + size)`
    /// (bus addresses, seen by the CPU at the same addresses).
    pub const fn with_pref64(mut self, base: u64, size: u64) -> Self {
        self.pref64 = Pool::new(base, size);
        self.xlat[PREF64] = Xlat { bus_base: base, size, delta: 0 };
        self
    }

    /// The host bridge shows the 32-bit window to the CPU starting at
    /// `cpu_base` instead of at its bus address.
    pub const fn with_mem32_at_cpu(mut self, cpu_base: u64) -> Self {
        self.xlat[MEM32].delta = cpu_base.wrapping_sub(self.xlat[MEM32].bus_base);
        self
    }

    /// The same for the 64-bit prefetchable window.
    pub const fn with_pref64_at_cpu(mut self, cpu_base: u64) -> Self {
        self.xlat[PREF64].delta = cpu_base.wrapping_sub(self.xlat[PREF64].bus_base);
        self
    }

    /// The CPU address of the BAR of `size` bytes at bus address `bus`: what
    /// the kernel maps and a driver dereferences. `None` when the BAR is not
    /// inside a window of the host bridge and the bridge translates (a bus
    /// address nothing forwards has no CPU address). Without translation a
    /// BAR a firmware placed outside the windows we know is reached at its
    /// own address.
    pub fn bar_cpu_addr(&self, bus: u64, size: u64) -> Option<u64> {
        if let Some(x) = self.xlat.iter().find(|x| x.holds(bus, size)) {
            return Some(bus.wrapping_add(x.delta));
        }
        self.xlat.iter().all(|x| x.delta == 0).then_some(bus)
    }

    /// Does a 64-bit prefetchable window exist?
    pub fn has_pref64(&self) -> bool {
        let (next, end) = self.pref64.span();
        next < end
    }

    /// The bus address for memory BAR `bar` of `bdf`: the one fixed for it
    /// ahead of time, else a fresh one. A prefetchable 64-bit BAR comes from
    /// the 64-bit window while it lasts; everything else (and the overflow)
    /// from the 32-bit window. `None` for an I/O BAR or an exhausted window.
    pub fn alloc_bar(&mut self, bdf: Bdf, bar: &Bar) -> Option<u64> {
        if bar.kind == BarKind::Io {
            return None;
        }
        if let Some(r) = self.reserved[..self.n_reserved].iter().find(|r| r.bdf == bdf && r.index == bar.index) {
            return Some(r.addr);
        }
        if bar.kind == BarKind::Mem64 && bar.prefetchable {
            if let Some(a) = self.pref64.alloc(bar.size) {
                return Some(a);
            }
        }
        self.mem32.alloc(bar.size)
    }

    /// Fix `addr` as the address of BAR `index` of `bdf`. `false` if the
    /// table is full.
    pub(crate) fn reserve(&mut self, bdf: Bdf, index: u8, addr: u64) -> bool {
        if self.n_reserved == MAX_RESERVED {
            return false;
        }
        self.reserved[self.n_reserved] = Reserved { bdf, index, addr };
        self.n_reserved += 1;
        true
    }

    /// Forget the addresses fixed inside `[base, base + size)` for functions
    /// on buses `bus_lo..=bus_hi`: the bridge window that was to cover them
    /// could not be programmed, so they are placed on demand instead of at
    /// an address no bridge forwards.
    pub(crate) fn release(&mut self, bus_lo: u8, bus_hi: u8, base: u64, size: u64) {
        let end = base.saturating_add(size);
        let mut kept = 0;
        for i in 0..self.n_reserved {
            let r = self.reserved[i];
            let behind = (bus_lo..=bus_hi).contains(&r.bdf.bus) && r.addr >= base && r.addr < end;
            if !behind {
                self.reserved[kept] = r;
                kept += 1;
            }
        }
        self.n_reserved = kept;
    }
}

// ---------------------------------------------------------------------
// Resolving the windows from firmware
// ---------------------------------------------------------------------

/// One host-bridge window as firmware states it: PCI bus addresses
/// `[bus_base, bus_base + size)` appear to the CPU at `cpu_base` (DT
/// `ranges`); the two differ on a host bridge that translates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostWindow {
    pub cpu_base: u64,
    pub bus_base: u64,
    pub size: u64,
}

/// What firmware states about the host bridge's memory windows; `None` for
/// a window it does not state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FirmwareWindows {
    pub mem32: Option<HostWindow>,
    pub mem64: Option<HostWindow>,
}

/// Where a resolved window came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowSource {
    /// Stated by firmware, bus == CPU addresses.
    Firmware,
    /// Firmware stated none; the built-in default.
    BuiltIn,
    /// Stated by firmware, and the host bridge translates: BARs get bus
    /// addresses, the CPU reaches them at `cpu_base`.
    Translated,
    /// The window lies beyond what the kernel can map; clipped to nothing.
    BeyondReach,
    /// A 32-bit window whose bus addresses all lie above 4 GiB (no 32-bit
    /// BAR or non-prefetchable bridge window can sit there); clipped to
    /// nothing.
    Above4G,
}

/// One resolved window: what is handed out, and why. `base` is the bus
/// address BARs are programmed from, `cpu_base` where the CPU sees it (equal
/// unless the host bridge translates).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedWindow {
    pub base: u64,
    pub cpu_base: u64,
    pub size: u64,
    pub source: WindowSource,
}

const NO_WINDOW: ResolvedWindow = ResolvedWindow { base: 0, cpu_base: 0, size: 0, source: WindowSource::BuiltIn };

/// What [`resolve_bar_window`] decided, for one console line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowReport {
    pub fw_name: &'static str,
    pub mem32: ResolvedWindow,
    /// `None`: no 64-bit window exists (the BARs that would use it fall
    /// back to the 32-bit one).
    pub pref64: Option<ResolvedWindow>,
}

impl fmt::Display for WindowReport {
    /// `mem32 0x40000000+0x40000000 (dtb), pref64 0x400000000+0x400000000 (dtb)`
    /// or, with no 64-bit window, `..., no pref64 window`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_one(f, "mem32", &self.mem32)?;
        match &self.pref64 {
            Some(w) => {
                f.write_str(", ")?;
                self.fmt_one(f, "pref64", w)
            }
            None => f.write_str(", no pref64 window"),
        }
    }
}

impl WindowReport {
    fn fmt_one(&self, f: &mut fmt::Formatter<'_>, name: &str, w: &ResolvedWindow) -> fmt::Result {
        write!(f, "{} {:#x}+{:#x}", name, w.base, w.size)?;
        if w.source == WindowSource::Translated {
            write!(f, " -> cpu {:#x}", w.cpu_base)?;
        }
        f.write_str(" (")?;
        match w.source {
            WindowSource::Firmware | WindowSource::Translated => f.write_str(self.fw_name)?,
            WindowSource::BuiltIn => f.write_str("built-in")?,
            WindowSource::BeyondReach => write!(f, "{}, beyond the kernel's address space", self.fw_name)?,
            WindowSource::Above4G => write!(f, "{}, above 4 GiB on the bus", self.fw_name)?,
        }
        f.write_str(")")
    }
}

/// Cut `[base, base + size)` to the addresses below `limit`.
fn clip(base: u64, size: u64, limit: u64) -> Option<u64> {
    if size == 0 || base >= limit {
        return None;
    }
    Some(size.min(limit - base))
}

/// Resolve one window. `reach` bounds the CPU addresses, `bus_limit` the bus
/// ones (`None`: unbounded); the window shrinks from the top to satisfy both.
fn resolve_one(
    fw: Option<HostWindow>,
    default: Option<(u64, u64)>,
    reach: u64,
    bus_limit: Option<u64>,
) -> Option<ResolvedWindow> {
    let (bus, cpu, size, source) = match fw {
        Some(w) => (w.bus_base, w.cpu_base, w.size, if w.cpu_base == w.bus_base { WindowSource::Firmware } else { WindowSource::Translated }),
        None => {
            let (b, s) = default?;
            (b, b, s, WindowSource::BuiltIn)
        }
    };
    // A window whose far end wraps the address space is not one.
    let size = if bus.checked_add(size).is_some() && cpu.checked_add(size).is_some() { size } else { 0 };
    let Some(size) = clip(cpu, size, reach) else {
        return Some(ResolvedWindow { source: WindowSource::BeyondReach, ..NO_WINDOW });
    };
    let Some(size) = clip(bus, size, bus_limit.unwrap_or(u64::MAX)) else {
        return Some(ResolvedWindow { source: WindowSource::Above4G, ..NO_WINDOW });
    };
    Some(ResolvedWindow { base: bus, cpu_base: cpu, size, source })
}

/// The windows BARs are placed from.
///
/// * `fw`: the host bridge's windows as firmware states them (`None`: no
///   firmware description at all, the defaults apply).
/// * `fw_name`: what to call that firmware in the report (`"dtb"`).
/// * `default_mem32` / `default_mem64`: where firmware states nothing
///   (QEMU `virt`'s own values, Kconfig on x86), bus == CPU addresses.
/// * `reach`: the first CPU address the kernel cannot map as device memory
///   (e.g. `1 << 39` for a 39-bit address space). A window past it is
///   dropped, one that straddles it is cut: a BAR the kernel cannot reach
///   is worse than one placed in the 32-bit window instead.
///
/// A window firmware translates (bus address != CPU address) is handed out
/// in BUS addresses, which is what BARs and bridge windows are programmed
/// with; [`BarWindow::bar_cpu_addr`] gives the CPU address to map. The
/// 32-bit window is also cut at 4 GiB of bus address. A 64-bit window that
/// comes out empty is no window ([`BarWindow::has_pref64`]).
pub fn resolve_bar_window(
    fw: Option<FirmwareWindows>,
    fw_name: &'static str,
    default_mem32: (u64, u64),
    default_mem64: Option<(u64, u64)>,
    reach: u64,
) -> (BarWindow, WindowReport) {
    let fw = fw.unwrap_or_default();
    let mem32 = resolve_one(fw.mem32, Some(default_mem32), reach, Some(1 << 32)).unwrap_or(NO_WINDOW);
    let pref64 = resolve_one(fw.mem64, default_mem64, reach, None);
    let mut window = BarWindow::new(mem32.base, mem32.size).with_mem32_at_cpu(mem32.cpu_base);
    if let Some(w) = pref64 {
        window = window.with_pref64(w.base, w.size).with_pref64_at_cpu(w.cpu_base);
    }
    (window, WindowReport { fw_name, mem32, pref64 })
}
