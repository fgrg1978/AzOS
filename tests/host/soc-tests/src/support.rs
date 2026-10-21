// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Test support: a flattened-device-tree builder, a register-trace bus and a
//! recording effect sink that share one ordered log.

use azos_soc::clk::{Clk, ClockTree};
use azos_soc::{Bus, Effect, EffectSink, Error, Refused};
use azos_thermal::k1_soc::K1Clocks;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

// ---- FDT builder ----

pub struct Builder {
    st: Vec<u8>,
    strs: Vec<u8>,
}

impl Builder {
    pub fn new() -> Self {
        let mut b = Builder { st: Vec::new(), strs: Vec::new() };
        b.begin("");
        b
    }

    pub fn begin(&mut self, name: &str) -> &mut Self {
        self.st.extend_from_slice(&1u32.to_be_bytes());
        self.st.extend_from_slice(name.as_bytes());
        self.st.push(0);
        self.pad();
        self
    }

    pub fn end(&mut self) -> &mut Self {
        self.st.extend_from_slice(&2u32.to_be_bytes());
        self
    }

    fn pad(&mut self) {
        while self.st.len() % 4 != 0 {
            self.st.push(0);
        }
    }

    pub fn prop(&mut self, name: &str, val: &[u8]) -> &mut Self {
        let off = match self.strs.windows(name.len() + 1).position(|w| &w[..name.len()] == name.as_bytes() && w[name.len()] == 0) {
            Some(o) => o,
            None => {
                let o = self.strs.len();
                self.strs.extend_from_slice(name.as_bytes());
                self.strs.push(0);
                o
            }
        };
        self.st.extend_from_slice(&3u32.to_be_bytes());
        self.st.extend_from_slice(&(val.len() as u32).to_be_bytes());
        self.st.extend_from_slice(&(off as u32).to_be_bytes());
        self.st.extend_from_slice(val);
        self.pad();
        self
    }

    pub fn flag(&mut self, name: &str) -> &mut Self {
        self.prop(name, &[])
    }

    pub fn cells(&mut self, name: &str, v: &[u32]) -> &mut Self {
        let bytes: Vec<u8> = v.iter().flat_map(|c| c.to_be_bytes()).collect();
        self.prop(name, &bytes)
    }

    pub fn strs(&mut self, name: &str, v: &[&str]) -> &mut Self {
        let mut bytes = Vec::new();
        for s in v {
            bytes.extend_from_slice(s.as_bytes());
            bytes.push(0);
        }
        self.prop(name, &bytes)
    }

    pub fn str(&mut self, name: &str, v: &str) -> &mut Self {
        self.strs(name, &[v])
    }

    /// `phandle = <ph>`.
    pub fn ph(&mut self, ph: u32) -> &mut Self {
        self.cells("phandle", &[ph])
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.end();
        self.st.extend_from_slice(&9u32.to_be_bytes());
        let off_st = 40 + 16; // header + one empty reservation entry
        let off_strs = off_st + self.st.len();
        let total = off_strs + self.strs.len();
        let mut out = Vec::new();
        for w in [0xd00d_feedu32, total as u32, off_st as u32, off_strs as u32, 40, 17, 16, 0, self.strs.len() as u32, self.st.len() as u32] {
            out.extend_from_slice(&w.to_be_bytes());
        }
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&self.st);
        out.extend_from_slice(&self.strs);
        out
    }
}

// ---- trace bus and recording sink ----

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ev {
    R(u64),
    W(u64, u32),
    E(Effect),
}

#[derive(Default)]
pub struct Log(pub RefCell<Vec<Ev>>);

impl Log {
    pub fn new() -> Rc<Log> {
        Rc::new(Log::default())
    }
    pub fn all(&self) -> Vec<Ev> {
        self.0.borrow().clone()
    }
    pub fn clear(&self) {
        self.0.borrow_mut().clear();
    }
    /// Register writes only.
    pub fn writes(&self) -> Vec<(u64, u32)> {
        self.0.borrow().iter().filter_map(|e| if let Ev::W(a, v) = e { Some((*a, *v)) } else { None }).collect()
    }
    pub fn reads(&self) -> Vec<u64> {
        self.0.borrow().iter().filter_map(|e| if let Ev::R(a) = e { Some(*a) } else { None }).collect()
    }
    pub fn effects(&self) -> Vec<Effect> {
        self.0.borrow().iter().filter_map(|e| if let Ev::E(x) = e { Some(*x) } else { None }).collect()
    }
}

pub type Hook = Box<dyn FnMut(&mut HashMap<u64, u32>, u64, u32)>;

pub struct TraceBus {
    pub regs: HashMap<u64, u32>,
    pub log: Rc<Log>,
    hook: Option<Hook>,
}

impl TraceBus {
    pub fn new(log: &Rc<Log>) -> Self {
        TraceBus { regs: HashMap::new(), log: log.clone(), hook: None }
    }
    pub fn with(mut self, addr: u64, val: u32) -> Self {
        self.regs.insert(addr, val);
        self
    }
    /// A model of the hardware: called after every write is stored.
    pub fn hook(mut self, h: Hook) -> Self {
        self.hook = Some(h);
        self
    }
}

impl Bus for TraceBus {
    fn read32(&mut self, addr: u64) -> u32 {
        self.log.0.borrow_mut().push(Ev::R(addr));
        self.regs.get(&addr).copied().unwrap_or(0)
    }
    fn write32(&mut self, addr: u64, val: u32) {
        self.log.0.borrow_mut().push(Ev::W(addr, val));
        self.regs.insert(addr, val);
        if let Some(h) = self.hook.as_mut() {
            h(&mut self.regs, addr, val);
        }
    }
}

/// Records each effect in the shared log; `refuse` says which ones it would
/// not take.
pub struct Sink {
    pub log: Rc<Log>,
    pub refuse: Box<dyn Fn(&Effect) -> bool>,
}

impl Sink {
    pub fn new(log: &Rc<Log>) -> Self {
        Sink { log: log.clone(), refuse: Box::new(|_| false) }
    }
    pub fn refusing(mut self, f: impl Fn(&Effect) -> bool + 'static) -> Self {
        self.refuse = Box::new(f);
        self
    }
}

impl EffectSink for Sink {
    fn commit(&mut self, e: &Effect) -> Result<(), Refused> {
        if (self.refuse)(e) {
            return Err(Refused { receipt: 77 });
        }
        self.log.0.borrow_mut().push(Ev::E(*e));
        Ok(())
    }
}

// ---- the board fixture ----

pub const OSC: u32 = 1;
pub const PLL0: u32 = 2;
pub const PLL2: u32 = 3;
pub const SYSCRG: u32 = 4;
pub const PMU: u32 = 5;
pub const VDD: u32 = 6;
pub const BUCK: u32 = 7;
pub const PINS: u32 = 8;
pub const UART0_PINS: u32 = 9;
pub const FLAT_PINS: u32 = 10;

pub const SYSCRG_BASE: u64 = 0x1302_0000;
pub const PMU_BASE: u64 = 0x1703_0000;

/// A VisionFive-2-shaped tree: three fixed clocks, the JH7110 clock/reset
/// controller and PMU, two rails, a pad controller with two states and a
/// UART that uses all of it.
pub fn board() -> Vec<u8> {
    let mut b = Builder::new();
    b.cells("#address-cells", &[2]).cells("#size-cells", &[2]);
    for (name, ph, hz) in [("oscillator", OSC, 24_000_000), ("pll0", PLL0, 1_000_000_000), ("pll2", PLL2, 1_188_000_000)] {
        b.begin(name).str("compatible", "fixed-clock").cells("#clock-cells", &[0]).cells("clock-frequency", &[hz]).ph(ph).end();
    }
    b.begin("soc").cells("#address-cells", &[2]).cells("#size-cells", &[2]).flag("ranges");

    b.begin("clock-controller@13020000")
        .strs("compatible", &["starfive,jh7110-syscrg"])
        .cells("reg", &[0, 0x1302_0000, 0, 0x10000])
        .cells("clocks", &[OSC, PLL0, PLL2])
        .strs("clock-names", &["osc", "pll0_out", "pll2_out"])
        .cells("#clock-cells", &[1])
        .cells("#reset-cells", &[1])
        .ph(SYSCRG)
        .end();
    b.begin("power-controller@17030000")
        .strs("compatible", &["starfive,jh7110-pmu"])
        .cells("reg", &[0, 0x1703_0000, 0, 0x10000])
        .cells("#power-domain-cells", &[1])
        .ph(PMU)
        .end();
    b.begin("regulator-vdd")
        .str("compatible", "regulator-fixed")
        .str("regulator-name", "vdd")
        .cells("regulator-min-microvolt", &[1_800_000])
        .cells("regulator-max-microvolt", &[1_800_000])
        .flag("regulator-always-on")
        .ph(VDD)
        .end();
    b.begin("regulator-buck")
        .str("compatible", "test,buck")
        .cells("regulator-min-microvolt", &[800_000])
        .cells("regulator-max-microvolt", &[1_200_000])
        .ph(BUCK)
        .end();

    b.begin("pinctrl@13040000")
        .str("compatible", "test,pinctrl")
        .cells("reg", &[0, 0x1304_0000, 0, 0x1000])
        .ph(PINS);
    b.begin("uart0-0").ph(UART0_PINS);
    b.begin("tx-pins").cells("pinmux", &[0x0102_0304]).flag("bias-disable").end();
    b.begin("rx-pins").cells("pinmux", &[0x0a0b_0c0d, 0x0a0b_0e0f]).flag("bias-pull-up").end();
    b.end();
    // A configuration node that is a group itself, no bias.
    b.begin("flat-0").cells("pinmux", &[0x0000_0501]).ph(FLAT_PINS).end();
    b.end();

    b.begin("serial@10000000")
        .str("compatible", "snps,dw-apb-uart")
        .cells("reg", &[0, 0x1000_0000, 0, 0x10000])
        .cells("clocks", &[SYSCRG, 146, SYSCRG, 145])
        .strs("clock-names", &["baudclk", "apb_pclk"])
        .cells("resets", &[SYSCRG, 74, SYSCRG, 75])
        .strs("reset-names", &["apb", "core"])
        .cells("power-domains", &[PMU, 2])
        .strs("power-domain-names", &["gpu"])
        .cells("vdd-supply", &[VDD])
        .cells("vcore-supply", &[BUCK])
        .strs("pinctrl-names", &["default", "sleep", "flat"])
        .cells("pinctrl-0", &[UART0_PINS])
        .cells("pinctrl-1", &[])
        .cells("pinctrl-2", &[FLAT_PINS])
        .end();
    b.end(); // soc
    b.finish()
}

pub fn uart(fdt: &azos_soc::Fdt<'_>) -> azos_soc::NodeId {
    by_path(fdt, "/soc/serial@10000000").expect("uart node")
}

/// The node at an absolute path; a component without a unit address matches
/// the first child of that name.
pub fn by_path(fdt: &azos_soc::Fdt<'_>, path: &str) -> Option<azos_soc::NodeId> {
    let mut n = azos_soc::NodeId(0);
    for comp in path.split('/').filter(|c| !c.is_empty()) {
        n = fdt.children(n).find(|&c| {
            fdt.name(c).is_some_and(|nm| nm == comp || (!comp.contains('@') && nm.split('@').next() == Some(comp)))
        })?;
    }
    Some(n)
}

// ---- the K1 clock access the tests own ----

/// `K1Clocks` over a clock tree, bus and effect sink the caller already
/// holds.
pub struct Direct<'a, 'p> {
    /// The clock tree.
    pub tree: &'a mut ClockTree<'p>,
    /// Register access.
    pub bus: &'a mut dyn Bus,
    /// Where the effects are recorded.
    pub fx: &'a mut dyn EffectSink,
}

impl K1Clocks for Direct<'_, '_> {
    fn rate(&mut self, clk: Clk) -> Result<u64, Error> {
        self.tree.rate(self.bus, clk)
    }
    fn round_rate(&mut self, clk: Clk, hz: u64) -> Result<u64, Error> {
        self.tree.round_rate(self.bus, clk, hz)
    }
    fn set_rate(&mut self, clk: Clk, hz: u64) -> Result<u64, Error> {
        self.tree.set_rate(self.bus, self.fx, clk, hz)
    }
}
