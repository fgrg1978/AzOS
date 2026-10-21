// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The K1 CPU cluster clocks and the PLL tree under them.
//!
//! # What a cluster clock is
//!
//! `CLK_CPU_Cn_CORE` (device-tree id 2 for cluster 0, 6 for cluster 1) is an
//! 8-way mux in `APMU_CPU_Cn_CLK_CTRL` (0x38C, 0x390), field `[2:0]`, with a
//! frequency-change bit 12 that the hardware clears when the switch is done
//! (`ccu-k1.c`: `CCU_MUX_FC_DEFINE(cpu_c0_core_clk, ..., BIT(12), 0, 3, ...)`;
//! `ccu_mix.c`: `ccu_mux_set_parent` writes the field, then
//! `ccu_mix_trigger_fc` sets the FC bit and polls it clear, 5 us apart, for
//! at most 10 ms). The mux inputs, in select order (`cpu_c0_clk_parents`):
//!
//! | sel | input | rate |
//! |---|---|---|
//! | 0 | `pll1_d4_614p4` | 614.4 MHz |
//! | 1 | `pll1_d3_819p2` | 819.2 MHz |
//! | 2 | `pll1_d6_409p6` | 409.6 MHz |
//! | 3 | `pll1_d5_491p52` | 491.52 MHz |
//! | 4 | `pll1_d2_1228p8` | 1228.8 MHz |
//! | 5 | `pll3_d3` | PLL3 / 3 |
//! | 6 | `pll2_d3` | 1000 MHz (PLL2 is 3 GHz) |
//! | 7 | `cpu_cn_hi` | PLL3 / 2 or PLL3 / 1 (bit 13 of the same register) |
//!
//! `CLK_CPU_Cn_HI` (ids 1, 5) is the select between `pll3_d2` (bit 13 = 0)
//! and `pll3_d1` (1), with no FC bit (`CCU_MUX_DEFINE(cpu_c0_hi_clk, ..., 13,
//! 1, 0)`). The ACE and TCM dividers (bits 8:6 and 11:9) are not modelled:
//! no consumer of the DVFS reads or moves them, and Linux's cpufreq does not
//! either; they stay as the firmware set them.
//!
//! # The tree under it
//!
//! * a PLL (`ccu_pll.c`): enable is bit 31 of `APBS_PLLn_SWCR3`, lock is a
//!   bit of `MPMU_POSR` (27, 28, 29 for PLL1..3; `k1-syscon.h`). Its rate is
//!   not computed: the registers are matched against the rate table
//!   (`SWCR1` whole, `SWCR3[30:0]`) and an unmatched PLL reports rate 0
//!   (Linux warns and reports 0). PLL1 and PLL2 have one entry (2457.6 and
//!   3000 MHz), PLL3 six (1600 .. 3200 MHz); the values are `ccu-k1.c`'s.
//! * a divider-gate (`CCU_FACTOR_GATE_DEFINE(pll1_d4, ...)`): bit N-1 of
//!   `APBS_PLLn_SWCR2` gates PLLn / N.
//! * a plain gate behind it in `MPMU_ACGR` (0x1024), e.g. `pll1_d4_614p4` is
//!   bit 15 (`CCU_GATE_DEFINE`).
//!
//! # What this provider does not do, on purpose
//!
//! It never reprograms a PLL. `ccu_pll` carries `CLK_SET_RATE_GATE` (a PLL
//! must be off while its rate changes) and a cluster may be running from the
//! PLL being asked about, so a rate change would need the cluster parked on
//! another source and the PLL relocked first; the K1's 1.6 GHz needs PLL3 at
//! 1.6 or 3.2 GHz, which is whatever the firmware left. `set_rate` therefore
//! picks, among the eight inputs, the one whose chain is running (every gate
//! on it open, its PLL enabled and locked, its rate non-zero) and whose rate
//! is closest to the request; ties go to the lower rate. If no input is
//! running it answers [`Error::Constraint`]. The HI select is left as the
//! firmware set it. This is also what Linux's `ccu_mix_determine_rate` does:
//! it looks at the parents' current rates and changes no parent.
//!
//! The window of a cluster clock is three register blocks, so the provider
//! owns three windows ([`K1Clk::windows`]): the APMU (the node itself), the
//! PLL block (the node `spacemit,k1-pll`) and the MPMU (the node the PLL
//! node's `spacemit,mpmu` names; `ccu_common.c`, `spacemit_ccu_probe`).
//!
//! [verify] on the board: that every one of the eight inputs the DVFS wants
//! is running at boot (the gates are left by the firmware); which PLL3 rate
//! the firmware leaves; whether the ACE clock needs to follow a cluster at
//! 1.6 GHz; the FC completion time; the order of the HI select against the
//! core select when both change.

use crate::clk::{ClockOps, Parent};
use crate::fdt::{Fdt, NodeId};
use crate::{Bus, Error, Result};

/// The clock controller whose node holds the CPU cluster clocks.
pub const APMU_COMPATIBLE: &str = "spacemit,k1-syscon-apmu";
/// The PLL block (`APBS` registers).
pub const PLL_COMPATIBLE: &str = "spacemit,k1-pll";

/// Device-tree ids (`spacemit,k1-syscon.h`): `CLK_CPU_C0_HI` .. `CLK_CPU_C1_CORE`.
pub const CLK_CPU_C0_HI: u32 = 1;
pub const CLK_CPU_C0_CORE: u32 = 2;
pub const CLK_CPU_C1_HI: u32 = 5;
pub const CLK_CPU_C1_CORE: u32 = 6;
/// The device-tree numbering of the APMU controller ends at `CLK_EMMC_BUS`
/// (61); the ids this provider invents for the tree under the clusters start
/// above it.
const INTERNAL: u32 = 64;

const PLL1: u32 = INTERNAL;
const PLL2: u32 = INTERNAL + 1;
const PLL3: u32 = INTERNAL + 2;
const P1_D2: u32 = INTERNAL + 3;
const P1_D3: u32 = INTERNAL + 4;
const P1_D4: u32 = INTERNAL + 5;
const P1_D5: u32 = INTERNAL + 6;
const P1_D6: u32 = INTERNAL + 7;
const P2_D3: u32 = INTERNAL + 8;
const P3_D1: u32 = INTERNAL + 9;
const P3_D2: u32 = INTERNAL + 10;
const P3_D3: u32 = INTERNAL + 11;
const G_1228: u32 = INTERNAL + 12;
const G_819: u32 = INTERNAL + 13;
const G_614: u32 = INTERNAL + 14;
const G_491: u32 = INTERNAL + 15;
const G_409: u32 = INTERNAL + 16;
const COUNT: u32 = INTERNAL + 17;

// APMU (the node itself): `k1-syscon.h`.
const APMU_CPU_C0_CLK_CTRL: u64 = 0x38c;
const APMU_CPU_C1_CLK_CTRL: u64 = 0x390;
/// `[2:0]` of `APMU_CPU_Cn_CLK_CTRL`: the core mux (`ccu-k1.c`).
const CORE_SEL_MASK: u32 = 0x7;
/// Bit 12: frequency change, cleared by the hardware (`ccu-k1.c`, `BIT(12)`).
const CORE_FC: u32 = 1 << 12;
/// Bit 13: the HI select (`ccu-k1.c`: `CCU_MUX_DEFINE(cpu_c0_hi_clk, ..., 13, 1, 0)`).
const HI_SEL: u32 = 1 << 13;

// PLL block (`spacemit,k1-pll`): `k1-syscon.h` APBS offsets.
const APBS_PLL1_SWCR1: u64 = 0x100;
const APBS_PLL2_SWCR1: u64 = 0x118;
const APBS_PLL3_SWCR1: u64 = 0x124;
/// `SWCR2` is `SWCR1 + 4`, `SWCR3` is `SWCR1 + 8` (`k1-syscon.h`, all three PLLs).
const SWCR2: u64 = 4;
const SWCR3: u64 = 8;
/// `ccu_pll.c`: `PLL_SWCR3_EN` and `PLL_SWCR3_MASK`.
const PLL_EN: u32 = 1 << 31;
const PLL_SWCR3_MASK: u32 = 0x7fff_ffff;

// MPMU: `k1-syscon.h`.
const MPMU_POSR: u64 = 0x0010;
const MPMU_ACGR: u64 = 0x1024;

/// Status reads before an FC switch or a PLL lock reports [`Error::Timeout`]:
/// Linux polls 5 us apart for 10 ms (`MIX_FC_TIMEOUT_US`) and 3 ms
/// (`PLL_TIMEOUT_US`); with no delay in the register interface, a read budget
/// stands for the time.
pub const POLL_BUDGET: u32 = 20_000;

/// One row of a PLL's rate table (`ccu-k1.c`).
struct PllRate {
    hz: u64,
    swcr1: u32,
    swcr3: u32,
}

const PLL1_RATES: &[PllRate] = &[PllRate { hz: 2_457_600_000, swcr1: 0x0050_dd64, swcr3: 0x330c_cccd }];
const PLL2_RATES: &[PllRate] = &[PllRate { hz: 3_000_000_000, swcr1: 0x0050_dd66, swcr3: 0x3fe0_0000 }];
const PLL3_RATES: &[PllRate] = &[
    PllRate { hz: 1_600_000_000, swcr1: 0x0050_cd61, swcr3: 0x43ea_aaab },
    PllRate { hz: 1_800_000_000, swcr1: 0x0050_cd61, swcr3: 0x4b00_0000 },
    PllRate { hz: 2_000_000_000, swcr1: 0x0050_dd62, swcr3: 0x2aea_aaab },
    PllRate { hz: 2_457_600_000, swcr1: 0x0050_dd64, swcr3: 0x330c_cccd },
    PllRate { hz: 3_000_000_000, swcr1: 0x0050_dd66, swcr3: 0x3fe0_0000 },
    PllRate { hz: 3_200_000_000, swcr1: 0x0050_dd67, swcr3: 0x43ea_aaab },
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    /// PLL `n` (1..=3).
    Pll(u8),
    /// PLL `n` / `div`, gated by `bit` of `APBS_PLLn_SWCR2`.
    Div { n: u8, bit: u8, div: u32 },
    /// A gate in `MPMU_ACGR`.
    Gate { bit: u8 },
    /// The HI select of cluster `c`.
    Hi(u8),
    /// The core mux of cluster `c`.
    Core(u8),
}

#[derive(Clone, Copy)]
struct Desc {
    id: u32,
    kind: Kind,
    /// The one input, for the clocks that have one.
    parent: Parent,
}

/// `ccu-k1.c` names in the comments. `pll1_d2` is `BIT(1)` .. `pll1_d6`
/// `BIT(5)` of `APBS_PLL1_SWCR2`; the MPMU gates are `CCU_GATE_DEFINE`s.
const TREE: &[Desc] = &[
    Desc { id: CLK_CPU_C0_HI, kind: Kind::Hi(0), parent: Parent::None },
    Desc { id: CLK_CPU_C0_CORE, kind: Kind::Core(0), parent: Parent::None },
    Desc { id: CLK_CPU_C1_HI, kind: Kind::Hi(1), parent: Parent::None },
    Desc { id: CLK_CPU_C1_CORE, kind: Kind::Core(1), parent: Parent::None },
    // The 24 MHz crystal is the controller's input 0 ("vctcxo_24m").
    Desc { id: PLL1, kind: Kind::Pll(1), parent: Parent::Input(0) },
    Desc { id: PLL2, kind: Kind::Pll(2), parent: Parent::Input(0) },
    Desc { id: PLL3, kind: Kind::Pll(3), parent: Parent::Input(0) },
    Desc { id: P1_D2, kind: Kind::Div { n: 1, bit: 1, div: 2 }, parent: Parent::Local(PLL1) },
    Desc { id: P1_D3, kind: Kind::Div { n: 1, bit: 2, div: 3 }, parent: Parent::Local(PLL1) },
    Desc { id: P1_D4, kind: Kind::Div { n: 1, bit: 3, div: 4 }, parent: Parent::Local(PLL1) },
    Desc { id: P1_D5, kind: Kind::Div { n: 1, bit: 4, div: 5 }, parent: Parent::Local(PLL1) },
    Desc { id: P1_D6, kind: Kind::Div { n: 1, bit: 5, div: 6 }, parent: Parent::Local(PLL1) },
    Desc { id: P2_D3, kind: Kind::Div { n: 2, bit: 2, div: 3 }, parent: Parent::Local(PLL2) },
    Desc { id: P3_D1, kind: Kind::Div { n: 3, bit: 0, div: 1 }, parent: Parent::Local(PLL3) },
    Desc { id: P3_D2, kind: Kind::Div { n: 3, bit: 1, div: 2 }, parent: Parent::Local(PLL3) },
    Desc { id: P3_D3, kind: Kind::Div { n: 3, bit: 2, div: 3 }, parent: Parent::Local(PLL3) },
    // pll1_d2_1228p8, pll1_d3_819p2, pll1_d4_614p4, pll1_d5_491p52, pll1_d6_409p6
    Desc { id: G_1228, kind: Kind::Gate { bit: 16 }, parent: Parent::Local(P1_D2) },
    Desc { id: G_819, kind: Kind::Gate { bit: 14 }, parent: Parent::Local(P1_D3) },
    Desc { id: G_614, kind: Kind::Gate { bit: 15 }, parent: Parent::Local(P1_D4) },
    Desc { id: G_491, kind: Kind::Gate { bit: 21 }, parent: Parent::Local(P1_D5) },
    Desc { id: G_409, kind: Kind::Gate { bit: 0 }, parent: Parent::Local(P1_D6) },
];

/// The core mux inputs, by select value (`cpu_c0_clk_parents`); `None`: the
/// cluster's HI clock.
const CORE_INPUTS: [Option<u32>; 8] =
    [Some(G_614), Some(G_819), Some(G_409), Some(G_491), Some(G_1228), Some(P3_D3), Some(P2_D3), None];

/// The inputs of the controller that [`Parent::Input`] indexes.
pub const INPUTS: &[&str] = &["vctcxo_24m"];

fn desc(id: u32) -> Result<&'static Desc> {
    TREE.iter().find(|d| d.id == id).ok_or(Error::BadSpec)
}

fn hi_of(c: u8) -> u32 {
    if c == 0 { CLK_CPU_C0_HI } else { CLK_CPU_C1_HI }
}

/// The K1 CPU clock complex: the three register blocks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct K1Clk {
    apmu: (u64, u64),
    pll: (u64, u64),
    mpmu: (u64, u64),
}

impl K1Clk {
    /// A complex with the given `(base, size)` windows.
    pub const fn new(apmu: (u64, u64), pll: (u64, u64), mpmu: (u64, u64)) -> Self {
        K1Clk { apmu, pll, mpmu }
    }

    /// From `node` if it is the (available) APMU controller: the PLL block
    /// is the first `spacemit,k1-pll` node, the MPMU the node its
    /// `spacemit,mpmu` names. All three must have a `reg`.
    pub fn from_dt(fdt: &Fdt<'_>, node: NodeId) -> Option<Self> {
        // Only the first APMU node of the tree is the complex: the window
        // bound of the boot step counts on one.
        if !fdt.is_available(node)
            || !fdt.is_compatible(node, APMU_COMPATIBLE)
            || fdt.find_compatible(APMU_COMPATIBLE) != Some(node)
        {
            return None;
        }
        let apmu = fdt.reg(node)?;
        let pll_node: NodeId = fdt.find_compatible(PLL_COMPATIBLE)?;
        let pll = fdt.reg(pll_node)?;
        let mpmu = fdt.reg(fdt.by_phandle(fdt.u32_prop(pll_node, "spacemit,mpmu")?)?)?;
        Some(K1Clk { apmu, pll, mpmu })
    }

    /// The register windows the provider reads and writes: APMU, PLL, MPMU.
    pub fn windows(&self) -> [(u64, u64); 3] {
        [self.apmu, self.pll, self.mpmu]
    }

    fn ctrl(&self, c: u8) -> u64 {
        self.apmu.0 + if c == 0 { APMU_CPU_C0_CLK_CTRL } else { APMU_CPU_C1_CLK_CTRL }
    }

    fn pll_regs(&self, n: u8) -> u64 {
        self.pll.0 + [APBS_PLL1_SWCR1, APBS_PLL2_SWCR1, APBS_PLL3_SWCR1][(n - 1) as usize]
    }

    fn pll_rates(n: u8) -> &'static [PllRate] {
        [PLL1_RATES, PLL2_RATES, PLL3_RATES][(n - 1) as usize]
    }

    /// `POSR_PLLn_LOCK` is bit 26 + n (`k1-syscon.h`: 27, 28, 29).
    fn locked(&self, bus: &mut dyn Bus, n: u8) -> bool {
        bus.read32(self.mpmu.0 + MPMU_POSR) & (1 << (26 + n as u32)) != 0
    }

    fn pll_rate(&self, bus: &mut dyn Bus, n: u8) -> u64 {
        let r = self.pll_regs(n);
        let swcr1 = bus.read32(r);
        let swcr3 = bus.read32(r + SWCR3) & PLL_SWCR3_MASK;
        Self::pll_rates(n).iter().find(|e| e.swcr1 == swcr1 && e.swcr3 == swcr3).map_or(0, |e| e.hz)
    }

    fn gate_enabled(&self, bus: &mut dyn Bus, d: &Desc) -> bool {
        match d.kind {
            Kind::Pll(n) => bus.read32(self.pll_regs(n) + SWCR3) & PLL_EN != 0,
            Kind::Div { n, bit, .. } => bus.read32(self.pll_regs(n) + SWCR2) & (1 << bit) != 0,
            Kind::Gate { bit } => bus.read32(self.mpmu.0 + MPMU_ACGR) & (1 << bit) != 0,
            Kind::Hi(_) | Kind::Core(_) => true,
        }
    }

    fn rmw(bus: &mut dyn Bus, addr: u64, mask: u32, val: u32) {
        let v = bus.read32(addr);
        bus.write32(addr, (v & !mask) | (val & mask));
    }

    /// The rate an input of a core mux makes right now and whether its chain
    /// is running (every gate open, the PLL enabled and locked). Rate 0 and
    /// "not running" are both unusable.
    fn source(&self, bus: &mut dyn Bus, c: u8, sel: usize) -> Result<(u64, bool)> {
        let mut cur = match CORE_INPUTS[sel] {
            Some(id) => id,
            None => hi_of(c),
        };
        let mut div = 1u64;
        let mut running = true;
        for _ in 0..crate::clk::MAX_DEPTH {
            let d = desc(cur)?;
            match d.kind {
                Kind::Pll(n) => {
                    running &= self.gate_enabled(bus, d) && self.locked(bus, n);
                    let hz = self.pll_rate(bus, n);
                    return Ok((hz / div, running && hz != 0));
                }
                Kind::Div { div: dv, .. } => {
                    running &= self.gate_enabled(bus, d);
                    div *= dv as u64;
                    cur = local(d.parent)?;
                }
                Kind::Gate { .. } => {
                    running &= self.gate_enabled(bus, d);
                    cur = local(d.parent)?;
                }
                Kind::Hi(_) => {
                    let sel = bus.read32(self.ctrl(c)) & HI_SEL != 0;
                    cur = if sel { P3_D1 } else { P3_D2 };
                }
                Kind::Core(_) => return Err(Error::Hardware),
            }
        }
        Err(Error::Depth)
    }

    /// The select value whose input is running and closest to `rate`, with
    /// the rate it makes.
    fn best(&self, bus: &mut dyn Bus, c: u8, rate: u64) -> Result<(usize, u64)> {
        let mut best: Option<(usize, u64)> = None;
        for sel in 0..CORE_INPUTS.len() {
            let (hz, running) = self.source(bus, c, sel)?;
            if !running {
                continue;
            }
            let better = match best {
                None => true,
                Some((_, b)) => {
                    let (dn, db) = (hz.abs_diff(rate), b.abs_diff(rate));
                    dn < db || (dn == db && hz < b)
                }
            };
            if better {
                best = Some((sel, hz));
            }
        }
        best.ok_or(Error::Constraint)
    }
}

fn local(p: Parent) -> Result<u32> {
    match p {
        Parent::Local(id) => Ok(id),
        _ => Err(Error::Hardware),
    }
}

impl ClockOps for K1Clk {
    fn count(&self) -> u32 {
        COUNT
    }

    fn modelled(&self, id: u32) -> bool {
        desc(id).is_ok()
    }

    fn input_names(&self) -> &'static [&'static str] {
        INPUTS
    }

    fn parent(&mut self, bus: &mut dyn Bus, id: u32) -> Result<Parent> {
        let d = desc(id)?;
        match d.kind {
            Kind::Core(c) => {
                let sel = (bus.read32(self.ctrl(c)) & CORE_SEL_MASK) as usize;
                Ok(match CORE_INPUTS[sel] {
                    Some(src) => Parent::Local(src),
                    None => Parent::Local(hi_of(c)),
                })
            }
            Kind::Hi(c) => Ok(Parent::Local(if bus.read32(self.ctrl(c)) & HI_SEL != 0 { P3_D1 } else { P3_D2 })),
            _ => Ok(d.parent),
        }
    }

    fn gated(&self, id: u32) -> bool {
        desc(id).is_ok_and(|d| matches!(d.kind, Kind::Pll(_) | Kind::Div { .. } | Kind::Gate { .. }))
    }

    fn enable(&mut self, bus: &mut dyn Bus, id: u32) -> Result<()> {
        let d = *desc(id)?;
        match d.kind {
            Kind::Pll(n) => {
                Self::rmw(bus, self.pll_regs(n) + SWCR3, PLL_EN, PLL_EN);
                for _ in 0..POLL_BUDGET {
                    if self.locked(bus, n) {
                        return Ok(());
                    }
                }
                Err(Error::Timeout)
            }
            Kind::Div { n, bit, .. } => {
                Self::rmw(bus, self.pll_regs(n) + SWCR2, 1 << bit, 1 << bit);
                Ok(())
            }
            Kind::Gate { bit } => {
                Self::rmw(bus, self.mpmu.0 + MPMU_ACGR, 1 << bit, 1 << bit);
                Ok(())
            }
            Kind::Hi(_) | Kind::Core(_) => Err(Error::Unsupported),
        }
    }

    fn disable(&mut self, bus: &mut dyn Bus, id: u32) -> Result<()> {
        let d = *desc(id)?;
        match d.kind {
            Kind::Pll(n) => Self::rmw(bus, self.pll_regs(n) + SWCR3, PLL_EN, 0),
            Kind::Div { n, bit, .. } => Self::rmw(bus, self.pll_regs(n) + SWCR2, 1 << bit, 0),
            Kind::Gate { bit } => Self::rmw(bus, self.mpmu.0 + MPMU_ACGR, 1 << bit, 0),
            Kind::Hi(_) | Kind::Core(_) => return Err(Error::Unsupported),
        }
        Ok(())
    }

    fn is_enabled(&mut self, bus: &mut dyn Bus, id: u32) -> Result<bool> {
        let d = *desc(id)?;
        Ok(self.gate_enabled(bus, &d))
    }

    fn rate(&mut self, bus: &mut dyn Bus, id: u32, parent_rate: u64) -> Result<u64> {
        let d = *desc(id)?;
        match d.kind {
            Kind::Pll(n) => Ok(self.pll_rate(bus, n)),
            Kind::Div { div, .. } => Ok(parent_rate / div as u64),
            Kind::Gate { .. } | Kind::Hi(_) | Kind::Core(_) => Ok(parent_rate),
        }
    }

    fn round_rate(&mut self, bus: &mut dyn Bus, id: u32, rate: u64, _parent_rate: u64) -> Result<u64> {
        match desc(id)?.kind {
            Kind::Core(c) => self.best(bus, c, rate).map(|(_, hz)| hz),
            _ => Err(Error::Unsupported),
        }
    }

    fn set_rate(&mut self, bus: &mut dyn Bus, id: u32, rate: u64, _parent_rate: u64) -> Result<u64> {
        let Kind::Core(c) = desc(id)?.kind else { return Err(Error::Unsupported) };
        let (sel, hz) = self.best(bus, c, rate)?;
        let ctrl = self.ctrl(c);
        if (bus.read32(ctrl) & CORE_SEL_MASK) as usize == sel {
            return Ok(hz);
        }
        // `ccu_mux_set_parent`: the select field, then the FC bit, then wait
        // for the hardware to clear it.
        Self::rmw(bus, ctrl, CORE_SEL_MASK, sel as u32);
        Self::rmw(bus, ctrl, CORE_FC, CORE_FC);
        for _ in 0..POLL_BUDGET {
            if bus.read32(ctrl) & CORE_FC == 0 {
                return Ok(hz);
            }
        }
        Err(Error::Timeout)
    }
}
