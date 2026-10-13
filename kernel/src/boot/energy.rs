// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! RFC-0051 E2 (kernel feature `energy`): resolve the energy model at boot and
//! hand it to the scheduler.
//!
//! Sources, in order: the installed topology's `[energy.domain.*]` sections,
//! then the DTB's `operating-points-v2` / `idle-states`, then none
//! (`azos_energy::resolve`). A model that fails validation is refused with
//! a `[ENERGY] ... REFUSED` line and the machine runs with none; nothing in
//! stages E0–E2 acts on a model, so a refusal costs nothing and a halt would.
//! The mode is the topology's alone (invariant I5).

use crate::*;

/// Resolve, validate, report and install. After `install_topology`, before
/// the scheduler starts.
pub(crate) fn install_energy(num_cpus: usize, dtb_ptr: usize) {
    let spec = azos_topology::get()
        .map(|t| *t.energy())
        .filter(|_| !cfg!(feature = "energy-model-canary"))
        .unwrap_or(azos_energy::EnergySpec::DEFAULT);
    let dt = if dtb_ptr != 0 {
        unsafe { azos_dtb::dtb_energy(azos_mm::addr::phys_to_virt(dtb_ptr) as *const u8) }
    } else {
        None
    };
    match &dt {
        Some(d) => kprintln!(
            "[ENERGY] dtb: {} cpu node(s), {} OPP table(s), {} idle state(s){}",
            d.cpus().len(), d.tables().len(), d.idle_states().len(),
            if d.truncated { " (truncated)" } else { "" },
        ),
        None => kprintln!("[ENERGY] dtb: none readable"),
    }
    let from_dtb = dt.as_ref().and_then(azos_energy::dt::from_dt);
    let (model, r) = azos_energy::resolve(&spec.model, from_dtb, num_cpus);
    if let Some(f) = r.topology_fault {
        azos_drv_sys::kwarn!("[ENERGY] topology model REFUSED: {:?} — running with no model", f);
    }
    if let Some(f) = r.dtb_fault {
        azos_drv_sys::kwarn!("[ENERGY] dtb model REFUSED: {:?} — running with no model", f);
    }
    let seams = azos_energy::Seams::select(&model, spec.mode);
    azos_sched::energy::install(model, spec.mode, seams);
    let tracker = azos_sched::energy::TRACKER;
    kprintln!(
        "[ENERGY] mode={} model={} domains={} opps={} tracker={} step={} ticks seams={:?}/{:?}/{:?}",
        spec.mode.as_str(), model.source.as_str(), model.domains().len(), model.opp_count(),
        match tracker {
            azos_energy::UtilTracker::Window { .. } => "window",
            azos_energy::UtilTracker::Pelt { .. } => "pelt",
        },
        tracker.step(), seams.placement, seams.governor, seams.idle,
    );
    for (i, d) in model.domains().iter().enumerate() {
        let top = d.opps().last().copied().unwrap_or(azos_energy::Opp::EMPTY);
        kprintln!(
            "[ENERGY] domain {}: cpus={:#x} opps={} top={} kHz cap={} {} mW idle={}",
            i, d.cpus, d.opps().len(), top.freq_khz, top.capacity, top.power_mw, d.idle_states().len(),
        );
    }
}
