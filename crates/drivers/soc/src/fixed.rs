// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The generic providers that have no registers: `fixed-clock` (an oscillator
//! or a board clock input with a `clock-frequency`) and `regulator-fixed` (a
//! rail with one voltage, always powered or switched by something this crate
//! does not model). Both exist so a consumer's `clocks` / `*-supply` lookup
//! resolves; neither touches the bus.

use crate::clk::{ClockOps, Parent};
use crate::fdt::{Fdt, NodeId};
use crate::regulator::{Io, RegulatorOps};
use crate::{Bus, Error, Result};

/// `compatible = "fixed-clock"`: one clock, always running, one rate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FixedClock {
    hz: u64,
}

impl FixedClock {
    pub const COMPATIBLE: &'static str = "fixed-clock";

    pub const fn new(hz: u64) -> Self {
        FixedClock { hz }
    }

    /// From `node`: its `clock-frequency`. `None` when the node is disabled,
    /// is not a `fixed-clock` or has no frequency.
    pub fn from_dt(fdt: &Fdt<'_>, node: NodeId) -> Option<Self> {
        if !fdt.is_available(node) || !fdt.is_compatible(node, Self::COMPATIBLE) {
            return None;
        }
        fdt.u32_prop(node, "clock-frequency").map(|hz| FixedClock::new(hz as u64))
    }
}

impl ClockOps for FixedClock {
    fn count(&self) -> u32 {
        1
    }
    fn parent(&mut self, _: &mut dyn Bus, id: u32) -> Result<Parent> {
        if id != 0 {
            return Err(Error::BadSpec);
        }
        Ok(Parent::None)
    }
    fn gated(&self, _: u32) -> bool {
        false
    }
    fn enable(&mut self, _: &mut dyn Bus, _: u32) -> Result<()> {
        Err(Error::Unsupported)
    }
    fn disable(&mut self, _: &mut dyn Bus, _: u32) -> Result<()> {
        Err(Error::Unsupported)
    }
    fn is_enabled(&mut self, _: &mut dyn Bus, _: u32) -> Result<bool> {
        Ok(true)
    }
    fn rate(&mut self, _: &mut dyn Bus, _: u32, _: u64) -> Result<u64> {
        Ok(self.hz)
    }
    fn set_rate(&mut self, _: &mut dyn Bus, _: u32, _: u64, _: u64) -> Result<u64> {
        Err(Error::Unsupported)
    }
}

/// `compatible = "regulator-fixed"`: one voltage (the node's
/// `regulator-min-microvolt`, which must equal its max). The enable state is
/// kept here: the rail's switch (a GPIO) is the board's business, so this
/// provider reports what the framework asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FixedRegulator {
    uv: u32,
    on: bool,
}

impl FixedRegulator {
    pub const COMPATIBLE: &'static str = "regulator-fixed";

    /// A rail at `uv` microvolts, `on` at boot.
    pub const fn new(uv: u32, on: bool) -> Self {
        FixedRegulator { uv, on }
    }

    /// From `node`: min and max microvolts must be present and equal.
    /// `regulator-boot-on` and `regulator-always-on` start it on.
    pub fn from_dt(fdt: &Fdt<'_>, node: NodeId) -> Option<Self> {
        if !fdt.is_available(node) || !fdt.is_compatible(node, Self::COMPATIBLE) {
            return None;
        }
        let min = fdt.u32_prop(node, "regulator-min-microvolt")?;
        let max = fdt.u32_prop(node, "regulator-max-microvolt")?;
        if min != max {
            return None;
        }
        let on = fdt.has_prop(node, "regulator-boot-on") || fdt.has_prop(node, "regulator-always-on");
        Some(FixedRegulator::new(min, on))
    }
}

impl RegulatorOps for FixedRegulator {
    fn enable(&mut self, _: &mut Io<'_>) -> Result<()> {
        self.on = true;
        Ok(())
    }
    fn disable(&mut self, _: &mut Io<'_>) -> Result<()> {
        self.on = false;
        Ok(())
    }
    fn is_enabled(&mut self, _: &mut Io<'_>) -> Result<bool> {
        Ok(self.on)
    }
    fn voltage(&mut self, _: &mut Io<'_>) -> Result<u32> {
        Ok(self.uv)
    }
    fn set_voltage(&mut self, _: &mut Io<'_>, uv: u32) -> Result<()> {
        if uv == self.uv { Ok(()) } else { Err(Error::Unsupported) }
    }
}
