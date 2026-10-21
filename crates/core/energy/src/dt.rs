// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The DTB source of the energy model: `azos_dtb::dtb_energy`'s raw
//! tables, phandles resolved, turned into an [`EnergyModel`].
//!
//! * **Domains.** CPUs whose `operating-points-v2` names one table marked
//!   `opp-shared` are one domain; a table without `opp-shared` gives each CPU
//!   naming it a domain of its own (it shares the table, not the clock).
//!   Domains are numbered in order of their first CPU; CPU `n` is the `n`-th
//!   CPU node in document order.
//! * **Capacity.** A CPU's top capacity is `capacity-dmips-mhz` times its
//!   table's top frequency, scaled so the largest is 1024; each OPP's
//!   capacity is that times `f / f_max` (at least 1). If any CPU lacks
//!   `capacity-dmips-mhz`, every CPU is taken as equal.
//! * **Power** is `opp-microwatt`, rounded to mW. A DTB that does not give it
//!   yields OPPs of power 0, which [`EnergyModel::validate`] refuses: no power
//!   is derived from `dynamic-power-coefficient`.
//! * **Idle states** are the domain's first CPU's `cpu-idle-states`, behind
//!   an implicit state 0, `wfi`: the DT never lists the architectural wait
//!   (as in Linux's `dt_idle_states`), and the idle seam
//!   (`Cpu::cpu_idle(depth)`) takes depth 0 as `wfi` and depth `d` as the
//!   `d`-th listed state. The exit latency of a listed state is
//!   `entry-latency-us + exit-latency-us` (Linux does the same: the time
//!   from the wake-up event back to running includes finishing the entry the
//!   wake-up interrupted, and invariant I3 wants the whole of it), target
//!   residency is `min-residency-us` (raised to the exit latency if the DTB
//!   gives less, which no sleep can pay back; [`residencies_raised`] names
//!   each such state so the boot can warn and leave a record of the DTB's
//!   mistake), power 0 (not known: the binding has no power). All of it is ISA-neutral: the same properties
//!   are read for `arm,idle-state` and `riscv,idle-state`.
//!
//! The result is still to be validated: [`crate::model::resolve`] does that.

use azos_dtb::{DtEnergy, DtIdleState, DtOpp, DtOppTable, DT_ENERGY_NAME, DT_ENERGY_OPPS};

use crate::model::{
    EnergyModel, IdleState, ModelFault, ModelSource, Opp, PerfDomain, CAPACITY_SCALE,
};

/// The model the DTB describes: `None` when no CPU names an OPP table,
/// `Some(Err)` when the tables cannot be turned into a model.
pub fn from_dt(dt: &DtEnergy) -> Option<Result<EnergyModel, ModelFault>> {
    let cpus = dt.cpus();
    let with = cpus.iter().filter(|c| c.opp_table != 0).count();
    if with == 0 {
        return None;
    }
    Some(build(dt, with == cpus.len()))
}

fn build(dt: &DtEnergy, all: bool) -> Result<EnergyModel, ModelFault> {
    if !all {
        return Err(ModelFault::DtPartialTables);
    }
    if dt.truncated || dt.tables().iter().any(|t| t.truncated) {
        return Err(ModelFault::DtTruncated);
    }
    let cpus = dt.cpus();
    let table_of = |phandle: u32| dt.tables().iter().find(|t| t.phandle == phandle);

    // Per CPU: its table (sorted OPPs) and top frequency.
    let mut sorted = [[DtOpp::EMPTY; DT_ENERGY_OPPS]; azos_dtb::DT_ENERGY_CPUS];
    let mut n_opps = [0usize; azos_dtb::DT_ENERGY_CPUS];
    let mut raw = [0u64; azos_dtb::DT_ENERGY_CPUS];
    let dmips_all = cpus.iter().all(|c| c.capacity_dmips_mhz != 0);
    for (i, c) in cpus.iter().enumerate() {
        let t = table_of(c.opp_table).ok_or(ModelFault::DtUnknownPhandle)?;
        n_opps[i] = sort_opps(t, &mut sorted[i]);
        let fmax_hz = if n_opps[i] == 0 { 0 } else { sorted[i][n_opps[i] - 1].hz };
        let dmips = if dmips_all { c.capacity_dmips_mhz as u64 } else { 1 };
        raw[i] = dmips.saturating_mul(fmax_hz / 1_000_000);
    }
    let raw_max = raw[..cpus.len()].iter().copied().max().unwrap_or(0).max(1);

    let mut m = EnergyModel::from_source(ModelSource::Dtb);
    let mut placed = 0u32;
    for (i, c) in cpus.iter().enumerate() {
        if placed & (1 << i) != 0 {
            continue;
        }
        let t = table_of(c.opp_table).ok_or(ModelFault::DtUnknownPhandle)?;
        let mut mask = 1u32 << i;
        if t.shared {
            for (j, o) in cpus.iter().enumerate().skip(i + 1) {
                if o.opp_table == c.opp_table {
                    mask |= 1 << j;
                }
            }
        }
        placed |= mask;
        let mut d = PerfDomain::new(mask);
        let cap_top = (raw[i] * CAPACITY_SCALE as u64 / raw_max) as u16;
        let ops = &sorted[i][..n_opps[i]];
        let fmax = ops.last().map_or(1, |o| o.hz).max(1);
        for o in ops {
            let khz = o.hz / 1_000;
            if khz == 0 || khz > u32::MAX as u64 {
                return Err(ModelFault::DtBadFrequency);
            }
            let cap = ((cap_top as u128 * o.hz as u128) / fmax as u128).max(1) as u16;
            let mw = ((o.microwatt + 500) / 1_000).min(u32::MAX as u64) as u32;
            d.push_opp(Opp { freq_khz: khz as u32, capacity: cap, power_mw: mw })
                .map_err(|_| ModelFault::TooManyOpps { domain: m.domains().len() as u8 })?;
        }
        // State 0 of every domain: the architectural wait, which a DTB does not
        // list. One microsecond to leave and to pay off, power unknown.
        d.push_idle(IdleState::new(b"wfi", 1, 1, 0)).map_err(|_| ModelFault::TooManyIdleStates { domain: m.domains().len() as u8 })?;
        for &ph in &c.idle_states[..c.n_idle as usize] {
            let s = dt.idle_states().iter().find(|s| s.phandle == ph).ok_or(ModelFault::DtUnknownPhandle)?;
            let mut buf = [0u8; 8];
            let name: &[u8] = if s.name_len > 0 {
                &s.name[..s.name_len as usize]
            } else {
                buf[..5].copy_from_slice(b"state");
                buf[5] = b'0' + (d.idle_states().len() as u8 % 10);
                &buf[..6]
            };
            let exit = exit_latency_us(s);
            d.push_idle(IdleState::new(name, exit, s.min_residency_us.max(exit), 0))
                .map_err(|_| ModelFault::TooManyIdleStates { domain: m.domains().len() as u8 })?;
        }
        m.push_domain(d).map_err(|_| ModelFault::TooManyDomains)?;
    }
    Ok(m)
}

/// The exit latency the model gives a listed idle state: `entry-latency-us`
/// plus `exit-latency-us`, at least 1 (see the module doc).
fn exit_latency_us(s: &DtIdleState) -> u32 {
    s.entry_latency_us.saturating_add(s.exit_latency_us).max(1)
}

/// A listed idle state whose `min-residency-us` the model raised to its exit
/// latency, because the DTB gave less (or none): a sleep shorter than the
/// exit latency never pays back, so the DTB is wrong, and the model keeps
/// the safe reading rather than refuse the whole table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResidencyRaised {
    /// The state's phandle.
    pub phandle: u32,
    /// `idle-state-name`, truncated; empty if absent.
    pub name: [u8; DT_ENERGY_NAME],
    /// Bytes used in `name`.
    pub name_len: u8,
    /// What the DTB said (0: absent).
    pub min_residency_us: u32,
    /// What the model uses instead (the state's exit latency).
    pub exit_latency_us: u32,
}

impl ResidencyRaised {
    /// The state's name (empty if the DTB gave none).
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// The idle states some CPU lists whose `min-residency-us` [`from_dt`] raises
/// to the exit latency, in document order. The boot warns for each and the
/// kernel log keeps the line: the one record of the DTB's mistake.
pub fn residencies_raised(dt: &DtEnergy) -> impl Iterator<Item = ResidencyRaised> + '_ {
    dt.idle_states()
        .iter()
        .filter(|s| dt.cpus().iter().any(|c| c.idle_states[..c.n_idle as usize].contains(&s.phandle)))
        .filter(|s| s.min_residency_us < exit_latency_us(s))
        .map(|s| ResidencyRaised {
            phandle: s.phandle,
            name: s.name,
            name_len: s.name_len,
            min_residency_us: s.min_residency_us,
            exit_latency_us: exit_latency_us(s),
        })
}

/// `t`'s OPPs into `out`, slowest first (the binding does not require any
/// order). Returns how many.
fn sort_opps(t: &DtOppTable, out: &mut [DtOpp; DT_ENERGY_OPPS]) -> usize {
    let n = t.n_opps as usize;
    out[..n].copy_from_slice(&t.opps[..n]);
    for i in 1..n {
        let mut j = i;
        while j > 0 && out[j - 1].hz > out[j].hz {
            out.swap(j - 1, j);
            j -= 1;
        }
    }
    n
}
