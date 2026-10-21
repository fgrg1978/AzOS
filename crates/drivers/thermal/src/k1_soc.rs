// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The SpacemiT K1's clusters over the SoC frameworks: [`K1Hw`] for
//! [`crate::k1::K1Opp`], and the plan that reads the clusters from the device
//! tree.
//!
//! # Two kinds of access
//!
//! * **The clock** is a register write in the clock framework
//!   (`azos_soc::clk`), made under the frameworks' lock like any other change
//!   and recorded as a write-ahead effect first. [`K1Clocks`] is that access,
//!   one operation at a time: the caller decides how the lock is taken for each
//!   (the kernel locks for the one operation, `LockedClocks` in
//!   `kernel/src/boot/thermal.rs`; the host tests borrow what they own).
//! * **The rail** is a P1 PMIC buck on an I2C bus. A voltage step is several
//!   transfers (the selector's write and read-back; the read of the voltage
//!   before it), hundreds of microseconds on the wire, which is more than a
//!   spin lock may be held (Kconfig `LOCK_MAX_HOLD_US`) and a sleeping lock
//!   may not be held across a device wait at all. So the rail does not go
//!   through the regulator manager: the plan keeps a copy of the buck
//!   ([`azos_soc::k1::P1Buck`], plain data) and its constraints, and
//!   [`SocK1Hw`] records the effect and drives the buck itself with no lock
//!   held. The write-ahead rule, the DT limits and the order are kept; what is
//!   given up is the manager's bookkeeping, which a DVFS step does not change
//!   (it neither enables nor disables the rail), and the assumption is that
//!   nothing else writes this rail's selector meanwhile (nothing does: a
//!   cluster's `cpu-supply` has no other consumer).
//!
//! Host-tested in `tests/host/soc-tests` (`k1` module) over the Jupiter
//! fixture, the K1 clock model and a P1 register model. The kernel builds one
//! [`SocK1Hw`] for each thermal tick (`kernel/src/boot/thermal.rs`).

use azos_dtb::DtEnergy;
use azos_energy::model::EnergyModel;
use azos_energy::opp::ActuateError;
use azos_soc::clk::{Clk, ClockTree};
use azos_soc::consumer::{self, Sel};
use azos_soc::effect::{self, issue, Class, Effect, Op};
use azos_soc::k1::P1Buck;
use azos_soc::regulator::{Reg, Regulators};
use azos_soc::{EffectSink, Error, Fdt, I2cBus, NodeId};

use crate::k1::{K1Hw, K1Table, MAX_K1_DOMAINS};

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

/// The clock framework as [`SocK1Hw`] uses it: one operation at a time, each
/// a brief register access.
pub trait K1Clocks {
    /// The rate of `clk` now, Hz.
    fn rate(&mut self, clk: Clk) -> Result<u64, Error>;
    /// The rate [`K1Clocks::set_rate`] would reach for `hz`; writes nothing.
    fn round_rate(&mut self, clk: Clk, hz: u64) -> Result<u64, Error>;
    /// Set `clk` to the closest rate it can make (recorded first) and return it.
    fn set_rate(&mut self, clk: Clk, hz: u64) -> Result<u64, Error>;
}

/// What one K1 cluster is made of in the frameworks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct K1Wires {
    /// The cluster's rate clock (an APMU `CPU_Cn` clock of the K1 clock
    /// controller).
    pub clk: Clk,
    /// The cluster's supply as the regulator framework numbers it. Only its
    /// identity is used: two clusters with the same one share a buck.
    pub rail: Reg,
    /// The buck itself, for [`SocK1Hw`] to drive.
    pub buck: P1Buck,
    /// The rail's `regulator-min-microvolt` and `regulator-max-microvolt`: the
    /// range [`SocK1Hw`] holds a request to (the manager would).
    pub min_uv: u32,
    /// See `min_uv`.
    pub max_uv: u32,
}

/// The SpacemiT K1's clusters over the SoC frameworks: [`K1Hw`] for
/// [`crate::k1::K1Opp`]. Built for one tick, like the CPU clock of the other
/// boards.
///
/// The clock moves through `clocks` (a write-ahead `KIND_CLOCK` effect each);
/// the rail through the buck, after a `KIND_REGULATOR` set-voltage effect
/// recorded in `fx` and with the voltage held to the rail's constraints:
/// a request over the DT ceiling is refused here as well as in the actuator.
pub struct SocK1Hw<'a, C: K1Clocks> {
    /// The clock framework.
    pub clocks: C,
    /// The I2C master the PMIC is reached through.
    pub i2c: &'a mut dyn I2cBus,
    /// Where the rail's effects are recorded.
    pub fx: &'a mut dyn EffectSink,
    /// The clock and rail of each cluster; `None`: the cluster is not there.
    pub wires: [Option<K1Wires>; MAX_K1_DOMAINS],
    /// Busy-wait this many microseconds (the kernel's timebase).
    pub delay: fn(u32),
}

impl<C: K1Clocks> SocK1Hw<'_, C> {
    fn wires(&self, domain: usize) -> Result<K1Wires, ActuateError> {
        self.wires.get(domain).copied().flatten().ok_or(ActuateError::Unsupported)
    }
}

impl<C: K1Clocks> K1Hw for SocK1Hw<'_, C> {
    fn cpu_khz(&mut self, domain: usize) -> Result<u32, ActuateError> {
        let w = self.wires(domain)?;
        let hz = self.clocks.rate(w.clk).map_err(actuate)?;
        u32::try_from(hz / 1000).map_err(|_| ActuateError::Fault(-5))
    }

    fn set_cpu_khz(&mut self, domain: usize, khz: u32) -> Result<(), ActuateError> {
        let w = self.wires(domain)?;
        let hz = u64::from(khz) * 1000;
        self.clocks.set_rate(w.clk, hz).map(|_| ()).map_err(actuate)
    }

    fn round_khz(&mut self, domain: usize, khz: u32) -> Result<u32, ActuateError> {
        let w = self.wires(domain)?;
        let hz = self.clocks.round_rate(w.clk, u64::from(khz) * 1000).map_err(actuate)?;
        u32::try_from(hz / 1000).map_err(|_| ActuateError::Fault(-5))
    }

    fn rail_of(&self, domain: usize) -> Option<u8> {
        self.wires(domain).ok().map(|w| w.rail.0)
    }

    fn voltage_uv(&mut self, domain: usize) -> Result<u32, ActuateError> {
        let w = self.wires(domain)?;
        w.buck.read_uv(&mut *self.i2c).map_err(actuate)
    }

    fn set_voltage_uv(&mut self, domain: usize, uv: u32) -> Result<(), ActuateError> {
        let w = self.wires(domain)?;
        if w.max_uv == 0 || uv < w.min_uv || uv > w.max_uv {
            return Err(ActuateError::Refused);
        }
        let e = Effect { kind: effect::KIND_REGULATOR, op: Op::SetVoltage, class: Class::Reversible, provider: w.rail.0, id: 0, value: u64::from(uv) };
        let i2c = &mut *self.i2c;
        issue(&mut *self.fx, e, || w.buck.write_uv(i2c, uv)).map_err(actuate)
    }

    fn delay_us(&mut self, us: u32) {
        (self.delay)(us);
    }
}

/// The K1 clusters as the device tree and the frameworks describe them:
/// which clock and rail each cluster has, and its OPP table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct K1Plan {
    /// Per domain of the energy model: clock and rail.
    pub wires: [Option<K1Wires>; MAX_K1_DOMAINS],
    /// Per domain: the table, checked against the rail's constraints.
    pub tables: [Option<K1Table>; MAX_K1_DOMAINS],
    /// Clusters left out: no table, no clock, no rail, a table the rail
    /// cannot run, or a domain past [`MAX_K1_DOMAINS`]. A cluster left out is
    /// not touched (its requests are `Unsupported`).
    pub left_out: u8,
    /// Per domain: OPPs of the energy model with no row in the cluster's
    /// table (a frequency the model has and the device tree's table does not
    /// carry at that exact kHz, or a row dropped for being over the rail). A
    /// request for one is refused, so the governor and the heat cannot use
    /// it: a model from another source than the same tree (the signed
    /// topology) with frequencies one kHz off leaves every OPP here.
    pub unmatched: [u8; MAX_K1_DOMAINS],
}

/// The node of the `n`-th CPU: the `n`-th child of `/cpus` with
/// `device_type = "cpu"`, in document order (the energy model's numbering of
/// CPUs).
fn nth_cpu(fdt: &Fdt<'_>, n: usize) -> Option<NodeId> {
    let cpus = fdt.children(NodeId(0)).find(|&c| fdt.name(c) == Some("cpus"))?;
    fdt.children(cpus)
        .filter(|&c| fdt.prop(c, "device_type").is_some_and(|v| v.starts_with(b"cpu\0")))
        .nth(n)
}

/// Read the K1 clusters from the device tree, one per performance domain of
/// `model` (the model is what the governor and the thermal caps name domains
/// by): the domain's first CPU's `clocks` entry 0 (the cluster's rate clock)
/// and `cpu-supply` (its rail), its `operating-points-v2` table from `dt`,
/// and the rail's `regulator-max-microvolt` and `regulator-ramp-delay` for the
/// table.
///
/// The Jupiter tree has two shared tables (one per cluster) and one
/// `cpu-supply` for all eight CPUs, so both domains come out with the same
/// `Reg`; that is what [`K1Hw::rail_of`] reports and the actuator holds the
/// shared rail with.
pub fn k1_plan(fdt: &Fdt<'_>, dt: &DtEnergy, model: &EnergyModel, clocks: &ClockTree<'_>, regs: &Regulators<'_>) -> K1Plan {
    let mut plan = K1Plan::default();
    for (domain, d) in model.domains().iter().enumerate() {
        if domain >= MAX_K1_DOMAINS {
            plan.left_out = plan.left_out.saturating_add(1);
            continue;
        }
        let wired = (|| {
            let cpu = nth_cpu(fdt, d.cpus.trailing_zeros() as usize)?;
            let clk = clocks.get(fdt, cpu, Sel::Index(0)).ok()?;
            let rail = regs.get_supply(fdt, cpu, "cpu").ok()?;
            let c = regs.constraints(rail)?;
            // The buck behind `cpu-supply`: a P1 buck, or the cluster is not
            // one this plan can drive.
            let buck = P1Buck::from_dt(fdt, consumer::phandle(fdt, cpu, "cpu-supply").ok()?)?;
            let ph = fdt.u32_prop(cpu, "operating-points-v2")?;
            let t = dt.tables().iter().find(|t| t.phandle == ph)?;
            Some((
                K1Wires { clk, rail, buck, min_uv: c.min_uv, max_uv: c.max_uv },
                K1Table::from_dt(t, c.max_uv, c.ramp_uv_per_us).ok()?,
            ))
        })();
        match wired {
            Some((w, t)) => {
                plan.unmatched[domain] = d.opps().iter().filter(|o| t.row(o.freq_khz).is_none()).count() as u8;
                plan.wires[domain] = Some(w);
                plan.tables[domain] = Some(t);
            }
            None => plan.left_out = plan.left_out.saturating_add(1),
        }
    }
    plan
}
