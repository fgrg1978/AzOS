// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Zones from the device tree: `azos_dtb::DtThermal`'s raw tables, phandles
//! resolved, turned into an `azos_energy::thermal::Thermal`.
//!
//! * **Sensor.** The board's `resolve` closure maps the `thermal-sensors`
//!   phandle and specifier cell to the sensor index its [`crate::sensor::SensorBank`]
//!   answers to. A zone whose sensor does not resolve is dropped: nothing
//!   could read it.
//! * **Trips.** `type` passive, active, hot, critical. A trip of an unknown
//!   type is dropped, and so is every map that names it. A zone left with no
//!   trip is dropped.
//! * **Cooling.** `cooling-device = <&cpuN min max>` names a CPU; the CPU's
//!   number is its position in `DtThermal::cpus`, which [`cpus_by_logical`]
//!   first reorders so that the position is the logical CPU (the numbering
//!   the energy model's masks use, the boot CPU first), and its domain is
//!   the energy model's performance domain whose mask holds that number. The cooling state is "OPP steps below the fastest" (cpufreq
//!   cooling's state 0 is the full table); `THERMAL_NO_LIMIT` is 0 as a
//!   minimum and the deepest step as a maximum, and a bound past the table
//!   is clamped to it. Several CPUs of one domain in one map are one map.
//!   A cooler that names an unknown CPU, a CPU in no domain or an unknown
//!   trip is dropped and counted.
//!
//! Dropping instead of refusing the whole tree is deliberate: a zone's
//! `critical` trip protects the silicon whether or not its cooling maps
//! resolve, so one bad map must not take the zone with it. What was dropped
//! is in [`Built`].

use azos_dtb::{
    DtThermal, DtZone, DT_THERMAL_NO_LIMIT, DT_TRIP_ACTIVE, DT_TRIP_CRITICAL, DT_TRIP_HOT, DT_TRIP_PASSIVE,
};
use azos_energy::model::EnergyModel;
use azos_energy::thermal::{CoolingMap, Thermal, ThermalFault, Trip, TripKind, Zone, MAX_TRIPS};

/// What [`build`] made and what it had to leave out.
pub struct Built {
    /// The zones that survived.
    pub thermal: Thermal,
    /// Zones dropped (no sensor, no trip, or more than a [`Thermal`] holds).
    pub zones_dropped: u8,
    /// Trips dropped (unknown type).
    pub trips_dropped: u8,
    /// Cooling-device entries dropped (see the module documentation).
    pub coolers_dropped: u8,
    /// The reader or a zone ran out of room.
    pub truncated: bool,
}

/// The kind of a trip's `type`, if known.
fn kind(k: u8) -> Option<TripKind> {
    match k {
        DT_TRIP_PASSIVE => Some(TripKind::Passive),
        DT_TRIP_ACTIVE => Some(TripKind::Active),
        DT_TRIP_HOT => Some(TripKind::Hot),
        DT_TRIP_CRITICAL => Some(TripKind::Critical),
        _ => None,
    }
}

/// Reorder `dt.cpus` so that entry `n` is the phandle of logical CPU `n`
/// (0 where no node is that CPU), using each node's `reg` and the boot's map
/// `logical` (the kernel's `boot::smp::cpu_of_dt_reg`). Read in document
/// order, a node's place is not its logical number: the boot CPU is logical
/// 0, and a disabled node (no CPU of the boot) takes a place too (audit
/// K2-M4, the same fix as `azos_energy::dt::from_dt`). Call it once, on a
/// table read from a DTB, before [`build`].
pub fn cpus_by_logical(dt: &mut DtThermal, logical: &dyn Fn(u64) -> Option<usize>) {
    let mut by = [0u32; azos_dtb::MAX_CPU_REG];
    let mut n = 0usize;
    for (&phandle, &reg) in dt.cpus().iter().zip(&dt.cpu_regs) {
        if let Some(l) = logical(reg).filter(|&l| l < by.len()) {
            by[l] = phandle;
            n = n.max(l + 1);
        }
    }
    dt.cpus = by;
    dt.cpu_regs = [0; azos_dtb::MAX_CPU_REG];
    dt.n_cpus = n as u8;
}

/// The number of the CPU whose node has `phandle`.
fn cpu_of(dt: &DtThermal, phandle: u32) -> Option<usize> {
    if phandle == 0 {
        return None;
    }
    dt.cpus().iter().position(|&p| p == phandle)
}

/// Turn `dt` into zones over `model`. `resolve(sensor_phandle, cell)` gives
/// the board's sensor index.
pub fn build(dt: &DtThermal, model: &EnergyModel, resolve: impl Fn(u32, u32) -> Option<u8>) -> Built {
    let mut b = Built {
        thermal: Thermal::new(),
        zones_dropped: 0,
        trips_dropped: 0,
        coolers_dropped: 0,
        truncated: dt.truncated,
    };
    for dz in dt.zones() {
        b.truncated |= dz.truncated;
        let Some(sensor) = resolve(dz.sensor, dz.sensor_cell).filter(|_| dz.sensor != 0) else {
            b.zones_dropped = b.zones_dropped.saturating_add(1);
            continue;
        };
        let zone = zone_of(dt, dz, model, sensor, &mut b);
        if zone.trips().is_empty() || b.thermal.push_zone(zone).is_err() {
            b.zones_dropped = b.zones_dropped.saturating_add(1);
        }
    }
    b
}

fn zone_of(dt: &DtThermal, dz: &DtZone, model: &EnergyModel, sensor: u8, b: &mut Built) -> Zone {
    let mut zone = Zone::new(dz.name(), sensor);
    zone.poll_passive_ms = dz.poll_passive_ms;
    zone.poll_ms = dz.poll_ms;

    // DT trip -> index in the zone (None: dropped).
    let mut index = [None::<u8>; MAX_TRIPS];
    for (i, t) in dz.trips().iter().enumerate() {
        let pushed = kind(t.kind).and_then(|k| {
            zone.push_trip(Trip { temp_mdeg: t.temp_mdeg, hyst_mdeg: t.hyst_mdeg, kind: k }).ok()
        });
        match pushed {
            Some(n) => index[i] = Some(n),
            None => b.trips_dropped = b.trips_dropped.saturating_add(1),
        }
    }
    for m in dz.maps() {
        let trip = dz
            .trips()
            .iter()
            .position(|t| t.phandle != 0 && t.phandle == m.trip)
            .and_then(|i| index[i]);
        for c in m.coolers() {
            let placed = (|| {
                let trip = trip?;
                let cpu = cpu_of(dt, c.phandle)?;
                // The domain masks cover CPUs 0..31 (`Kconfig.limits`): a CPU
                // past that is in no domain.
                let bit = u32::try_from(cpu).ok().and_then(|c| 1u32.checked_shl(c))?;
                let dom = model.domains().iter().position(|d| d.cpus & bit != 0)?;
                let deepest = model.domains()[dom].opps().len().checked_sub(1)? as u32;
                let min = if c.min == DT_THERMAL_NO_LIMIT { 0 } else { c.min.min(deepest) };
                let max = if c.max == DT_THERMAL_NO_LIMIT { deepest } else { c.max.min(deepest) };
                let map = CoolingMap { trip, domain: dom as u8, min_state: min.min(max) as u8, max_state: max as u8 };
                Some(map)
            })();
            match placed {
                // Another CPU of the same domain under the same trip: the
                // same cap, already there.
                Some(map) if zone.maps().iter().any(|x| x.trip == map.trip && x.domain == map.domain) => {}
                Some(map) => match zone.push_map(map, model) {
                    Ok(()) => {}
                    Err(ThermalFault::TooManyMaps) | Err(_) => {
                        b.coolers_dropped = b.coolers_dropped.saturating_add(1);
                    }
                },
                None => b.coolers_dropped = b.coolers_dropped.saturating_add(1),
            }
        }
    }
    zone
}
