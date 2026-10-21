// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The CPU clock over the SoC clock framework: [`jh7110::CpuClock`]
//! implemented with a clock of the [`azos_soc`] tree.
//!
//! One thermal step is one `set_cpu_khz`. The register write in it goes
//! through the framework, so it is a write-ahead effect (a `KIND_CLOCK`
//! set-rate) like any other clock change: the cap that cools the machine is on
//! the flight recorder before the clock moves.
//!
//! # The supply is not moved
//!
//! No regulator provider can move the cluster's rail today (the only one is
//! the fixed one, which has no register), so the voltage is whatever firmware
//! left. The clock may then go down from where it was at boot and back up to
//! it, never above: `ceiling_khz` is the rate read at boot, the only one the
//! unmoved rail is known to carry. A request above it is refused
//! ([`ActuateError::Refused`]), which the thermal runtime counts like a clock
//! that will not move. A board whose rail can be moved adds the voltage step
//! (rail first going up, clock first going down) together with its regulator
//! provider, not before.
//!
//! # Users
//!
//! Host-tested (`tests/host/soc-tests`, `thermal` module). The kernel's thermal
//! task (`kernel/src/boot/thermal.rs`) builds one per tick on a board with the
//! frameworks (the VisionFive 2): [`cpu_clock`] finds the clock the first CPU's
//! node names, and the rate read at boot is the `ceiling_khz`.

use azos_energy::opp::ActuateError;
use azos_soc::clk::{Clk, ClockTree};
use azos_soc::consumer::Sel;
use azos_soc::fdt::{Fdt, NodeId};
use azos_soc::{Bus, EffectSink, Error};

use crate::jh7110::CpuClock;

/// The CPU clock of a board that has the SoC frameworks. Built for one tick
/// from the kernel's clock tree, bus and effect sink.
pub struct SocCpuClock<'a, 'p> {
    /// The clock tree.
    pub tree: &'a mut ClockTree<'p>,
    /// Register access.
    pub bus: &'a mut dyn Bus,
    /// Where the effects are recorded.
    pub fx: &'a mut dyn EffectSink,
    /// The clock the cluster runs from (a divider of the CPU root).
    pub clk: Clk,
    /// The fastest clock the unmoved supply is known to carry, kHz.
    pub ceiling_khz: u32,
}

/// What a framework error means to the thermal runtime: a request the
/// hardware or the sink turned down is `Refused`; a timeout or a hardware
/// fault is a transport failure with the errno-style code of the cause.
fn actuate(e: Error) -> ActuateError {
    match e {
        Error::Timeout => ActuateError::Fault(-110),
        Error::Hardware => ActuateError::Fault(-5),
        _ => ActuateError::Refused,
    }
}

/// The clock the cluster runs from: the first entry of the `clocks` of the
/// first `device_type = "cpu"` node under `/cpus`. The SoCs this crate has a
/// board object for (the JH7110) run every core from one clock, so the first
/// CPU's is the cluster's. `None` when the tree has no such node, or it names
/// no clock the manager has a provider for.
pub fn cpu_clock(fdt: &Fdt<'_>, tree: &ClockTree<'_>) -> Option<Clk> {
    let root = NodeId(0);
    let cpus = fdt.children(root).find(|&n| fdt.name(n) == Some("cpus"))?;
    let cpu = fdt.children(cpus).find(|&n| fdt.prop(n, "device_type").is_some_and(|v| v.starts_with(b"cpu\0")))?;
    tree.get(fdt, cpu, Sel::Index(0)).ok()
}

impl SocCpuClock<'_, '_> {
    fn set_clock(&mut self, khz: u32) -> Result<(), ActuateError> {
        let hz = u64::from(khz) * 1000;
        self.tree.set_rate(self.bus, self.fx, self.clk, hz).map(|_| ()).map_err(actuate)
    }
}

impl CpuClock for SocCpuClock<'_, '_> {
    fn set_cpu_khz(&mut self, khz: u32) -> Result<(), ActuateError> {
        if khz > self.ceiling_khz {
            return Err(ActuateError::Refused);
        }
        self.set_clock(khz)
    }
}
