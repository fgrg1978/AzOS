// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The JH7110 system clock generator (SYSCRG).
//!
//! One 32-bit register per clock at `base + 4 * id` (TRM 2.8.1, Tables 2-50
//! to 2-239: the register offset of every clock is `4 * id`):
//!
//! ```text
//!  31      clk_icg: gate open (1) or closed (0); only on gated clocks
//!  30      reserved (clk_polarity only on the inverter clocks, not in the table)
//!  29:24   clk_mux_sel: index into the clock's parents; only on muxes
//!  23:0    clk_divcfg: rate = parent / div; only on dividers
//! ```
//!
//! A clock is one of: a gate, a divider, a gate with a divider, or a mux;
//! the table says which and where its input comes from. The table below
//! holds the clocks the boot path of the VisionFive 2 touches (CPU and bus
//! roots, the AXI/AHB/APB chain, the UARTs).
//!
//! What the register tables confirm (field presence and widths, the mux
//! inputs, the largest divider the TRM allows): every `Kind` and `max` below,
//! with the table number next to the clock. Parents come from the clock
//! structure of TRM 2.5.5 (Figure 2-4: root muxes, then
//! bus_root -> axi_cfg0 (/3) -> stg_axiahb (/2) -> AHB 0/1 and the APB
//! divider (/4, 51.2 MHz)). The PLLs are not in this block: `pll0_out`..
//! `pll2_out` are inputs, provided by the PLL controller node the `clocks`
//! property names.

use crate::clk::{ClockOps, Parent};
use crate::{Bus, Error, Result};

pub const SYSCRG_COMPATIBLE: &str = "starfive,jh7110-syscrg";

const ENABLE: u32 = 1 << 31;
const MUX_SHIFT: u32 = 24;
/// `clk_mux_sel` is `[29:24]` in every mux register (Table 2-50 and kin).
const MUX_MASK: u32 = 0x3f << MUX_SHIFT;
const DIV_MASK: u32 = 0x00ff_ffff;

/// `clock-names` of the controller's inputs, in [`Parent::Input`] order.
/// [verify] The names are the device-tree binding's, not the TRM's (the TRM
/// has no property names); the oscillator and PLL0..2 are the inputs of
/// Figure 2-4.
pub const INPUTS: &[&str] = &["osc", "pll0_out", "pll1_out", "pll2_out"];
const OSC: Parent = Parent::Input(0);
const PLL0: Parent = Parent::Input(1);
const PLL2: Parent = Parent::Input(3);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Gate,
    /// `max` is the largest divider the hardware field is used with.
    Div { max: u32 },
    GateDiv { max: u32 },
    /// Parent chosen by the select field.
    Mux,
}

#[derive(Clone, Copy, Debug)]
pub struct Desc {
    pub id: u32,
    pub name: &'static str,
    pub kind: Kind,
    /// One entry, or one per select value for a mux.
    pub parents: &'static [Parent],
}

macro_rules! clk {
    ($id:expr, $name:expr, $kind:expr, [$($p:expr),+]) => {
        Desc { id: $id, name: $name, kind: $kind, parents: &[$($p),+] }
    };
}

/// Sorted by id. `Kind`, `max` and the mux inputs are from the register
/// table named on each line; parents are described in the module doc.
pub const SYS_CLOCKS: &[Desc] = &[
    // T2-50: mux osc / pll0.
    clk!(0, "cpu_root", Kind::Mux, [OSC, PLL0]),
    // T2-51: divider, max 7.
    clk!(1, "cpu_core", Kind::Div { max: 7 }, [Parent::Local(0)]),
    // T2-52: divider, max 2.
    clk!(2, "cpu_bus", Kind::Div { max: 2 }, [Parent::Local(1)]),
    // T2-55: mux osc / pll2.
    clk!(5, "bus_root", Kind::Mux, [OSC, PLL2]),
    // T2-57: divider, max 3.
    clk!(7, "axi_cfg0", Kind::Div { max: 3 }, [Parent::Local(5)]),
    // T2-58: divider, max 2.
    clk!(8, "stg_axiahb", Kind::Div { max: 2 }, [Parent::Local(7)]),
    // T2-59, T2-60: gates.
    clk!(9, "ahb0", Kind::Gate, [Parent::Local(8)]),
    clk!(10, "ahb1", Kind::Gate, [Parent::Local(8)]),
    // T2-61: divider, max 8. [verify] Figure 2-4 hangs the APB divider off
    // the stg_axiahb net; whether it sits behind the ahb1 gate is not
    // visible in the figure, the model keeps it behind ahb1.
    clk!(11, "apb_bus_func", Kind::Div { max: 8 }, [Parent::Local(10)]),
    // T2-62: gate.
    clk!(12, "apb0", Kind::Gate, [Parent::Local(11)]),
    // T2-195..T2-200: UART 0..2 APB and core gates. UART 3..5 cores
    // (T2-202, T2-204, T2-206) are gates with a divider and are not in the
    // table: nothing on the boot path uses them.
    clk!(145, "uart0_apb", Kind::Gate, [Parent::Local(12)]),
    clk!(146, "uart0_core", Kind::Gate, [OSC]),
    clk!(147, "uart1_apb", Kind::Gate, [Parent::Local(12)]),
    clk!(148, "uart1_core", Kind::Gate, [OSC]),
    clk!(149, "uart2_apb", Kind::Gate, [Parent::Local(12)]),
    clk!(150, "uart2_core", Kind::Gate, [OSC]),
];

/// The SYSCRG clock register model at `base`.
pub struct Jh7110Clk {
    base: u64,
}

impl Jh7110Clk {
    /// The controller whose registers start at `base` (`0x1302_0000` on the
    /// VisionFive 2, TRM Table 2-4 "System CRG"; the device tree's `reg` is
    /// the authority).
    pub const fn new(base: u64) -> Self {
        Jh7110Clk { base }
    }

    /// From the node's `reg`, if it is a `starfive,jh7110-syscrg`.
    pub fn from_dt(fdt: &crate::Fdt<'_>, node: crate::NodeId) -> Option<Self> {
        if !fdt.is_available(node) || !fdt.is_compatible(node, SYSCRG_COMPATIBLE) {
            return None;
        }
        fdt.reg(node).map(|(base, _)| Jh7110Clk::new(base))
    }

    fn desc(id: u32) -> Result<&'static Desc> {
        SYS_CLOCKS.iter().find(|d| d.id == id).ok_or(Error::BadSpec)
    }

    fn reg(&self, id: u32) -> u64 {
        self.base + 4 * id as u64
    }

    fn rmw(&self, bus: &mut dyn Bus, id: u32, mask: u32, val: u32) {
        let a = self.reg(id);
        let v = bus.read32(a);
        bus.write32(a, (v & !mask) | (val & mask));
    }
}

impl ClockOps for Jh7110Clk {
    fn count(&self) -> u32 {
        SYS_CLOCKS.iter().map(|d| d.id).max().map_or(0, |m| m + 1)
    }

    fn input_names(&self) -> &'static [&'static str] {
        INPUTS
    }

    fn parent(&mut self, bus: &mut dyn Bus, id: u32) -> Result<Parent> {
        let d = Self::desc(id)?;
        if d.kind == Kind::Mux {
            let sel = ((bus.read32(self.reg(id)) & MUX_MASK) >> MUX_SHIFT) as usize;
            return d.parents.get(sel).copied().ok_or(Error::Hardware);
        }
        Ok(d.parents[0])
    }

    fn gated(&self, id: u32) -> bool {
        Self::desc(id).is_ok_and(|d| matches!(d.kind, Kind::Gate | Kind::GateDiv { .. }))
    }

    fn enable(&mut self, bus: &mut dyn Bus, id: u32) -> Result<()> {
        Self::desc(id)?;
        self.rmw(bus, id, ENABLE, ENABLE);
        Ok(())
    }

    fn disable(&mut self, bus: &mut dyn Bus, id: u32) -> Result<()> {
        Self::desc(id)?;
        self.rmw(bus, id, ENABLE, 0);
        Ok(())
    }

    fn is_enabled(&mut self, bus: &mut dyn Bus, id: u32) -> Result<bool> {
        Self::desc(id)?;
        Ok(bus.read32(self.reg(id)) & ENABLE != 0)
    }

    fn rate(&mut self, bus: &mut dyn Bus, id: u32, parent_rate: u64) -> Result<u64> {
        match Self::desc(id)?.kind {
            Kind::Gate | Kind::Mux => Ok(parent_rate),
            Kind::Div { .. } | Kind::GateDiv { .. } => {
                let div = (bus.read32(self.reg(id)) & DIV_MASK) as u64;
                Ok(if div == 0 { 0 } else { parent_rate / div })
            }
        }
    }

    fn set_rate(&mut self, bus: &mut dyn Bus, id: u32, rate: u64, parent_rate: u64) -> Result<u64> {
        match Self::desc(id)?.kind {
            Kind::Div { max } | Kind::GateDiv { max } => {
                if rate == 0 || parent_rate == 0 {
                    return Err(Error::BadSpec);
                }
                // Closest divider, 1..=max.
                let div = ((parent_rate + rate / 2) / rate).clamp(1, max as u64) as u32;
                self.rmw(bus, id, DIV_MASK, div);
                Ok(parent_rate / div as u64)
            }
            Kind::Gate | Kind::Mux => {
                if rate == parent_rate { Ok(rate) } else { Err(Error::Unsupported) }
            }
        }
    }
}
