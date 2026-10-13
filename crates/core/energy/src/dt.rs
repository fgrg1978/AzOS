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
//! * **Idle states** are the domain's first CPU's `cpu-idle-states`, exit
//!   latency from `exit-latency-us`, target residency from
//!   `min-residency-us`, power 0 (not known: the binding has no power).
//!
//! The result is still to be validated: [`crate::model::resolve`] does that.

use azos_dtb::{DtEnergy, DtOpp, DtOppTable, DT_ENERGY_OPPS};

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
    let mut sorted = [[DtOpp { hz: 0, microwatt: 0 }; DT_ENERGY_OPPS]; azos_dtb::DT_ENERGY_CPUS];
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
            d.push_idle(IdleState::new(name, s.exit_latency_us, s.min_residency_us, 0))
                .map_err(|_| ModelFault::TooManyIdleStates { domain: m.domains().len() as u8 })?;
        }
        m.push_domain(d).map_err(|_| ModelFault::TooManyDomains)?;
    }
    Ok(m)
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
